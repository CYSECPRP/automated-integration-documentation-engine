"""GitHub REST API integration: a careful client plus a repository collector."""

from __future__ import annotations

import base64
import contextlib
import re
import time
from collections.abc import Callable, Mapping, Sequence
from collections.abc import Collection as CollectionOf
from typing import Any
from urllib.parse import quote

import httpx
import yaml

from govflow import __version__
from govflow.connectors.base import Collection
from govflow.models import Resource

API_VERSION = "2022-11-28"
ADMIN_REASON = "needs admin access to the repository (token with Administration: read)"
SECURITY_POLICY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")
CODEOWNERS_PATHS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS")
DEPENDABOT_PATHS = (".github/dependabot.yml", ".github/dependabot.yaml")
_FULL_SHA = re.compile(r"[0-9a-f]{40}")

Query = Mapping[str, str | int]


class GitHubAPIError(RuntimeError):
    """A GitHub API call failed. Messages never include credentials."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def _error(method: str, path: str, response: httpx.Response) -> GitHubAPIError:
    status = response.status_code
    reason = ""
    if status == 401:
        reason = "authentication failed (check the token)"
    elif status in (403, 429) and response.headers.get("x-ratelimit-remaining") == "0":
        reason = "rate limit exhausted"
    else:
        with contextlib.suppress(ValueError):
            body = response.json()
            if isinstance(body, dict):
                reason = str(body.get("message", ""))[:200]
    suffix = f": {reason}" if reason else ""
    return GitHubAPIError(f"{method} {path} returned HTTP {status}{suffix}", status)


class GitHubClient:
    def __init__(
        self,
        token: str | None = None,
        *,
        base_url: str = "https://api.github.com",
        transport: httpx.BaseTransport | None = None,
        max_retries: int = 3,
        max_wait: float = 60.0,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
    ) -> None:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": f"govflow/{__version__}",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.authenticated = bool(token)
        self._client = httpx.Client(
            base_url=base_url, headers=headers, transport=transport, timeout=30.0
        )
        self._max_retries = max_retries
        self._max_wait = max_wait
        self._sleep = sleep
        self._now = now

    def __repr__(self) -> str:
        base_url = str(self._client.base_url)
        return f"GitHubClient(base_url={base_url!r}, authenticated={self.authenticated})"

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(
        self, method: str, path: str, *, params: Query | None = None, json: Any = None
    ) -> httpx.Response:
        attempt = 0
        while True:
            try:
                response = self._client.request(method, path, params=params, json=json)
            except httpx.HTTPError as exc:
                raise GitHubAPIError(f"{method} {path} failed: {type(exc).__name__}") from exc
            wait = self._retry_delay(response)
            if wait is None or attempt >= self._max_retries:
                return response
            attempt += 1
            self._sleep(wait)

    def _retry_delay(self, response: httpx.Response) -> float | None:
        headers = response.headers
        limited = response.status_code == 429 or (
            response.status_code == 403
            and (headers.get("x-ratelimit-remaining") == "0" or "retry-after" in headers)
        )
        if not limited:
            return None
        try:
            if "retry-after" in headers:
                wait = float(headers["retry-after"])
            elif "x-ratelimit-reset" in headers:
                wait = max(0.0, float(headers["x-ratelimit-reset"]) - self._now()) + 1.0
            else:
                wait = 60.0
        except ValueError:
            wait = self._max_wait
        return wait if wait <= self._max_wait else None

    def get_json(
        self, path: str, *, params: Query | None = None, allow: CollectionOf[int] = ()
    ) -> tuple[int, Any]:
        response = self.request("GET", path, params=params)
        if response.status_code == 200:
            return 200, response.json()
        if response.status_code in allow:
            return response.status_code, None
        raise _error("GET", path, response)

    def send_json(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any],
        *,
        expected: CollectionOf[int] = (200, 201),
    ) -> Any:
        response = self.request(method, path, json=dict(payload))
        if response.status_code in expected:
            return response.json() if response.content else None
        raise _error(method, path, response)

    def status(self, path: str) -> int:
        return self.request("GET", path).status_code

    def paginate(self, path: str, *, params: Query | None = None) -> list[Any]:
        items: list[Any] = []
        url: str | None = path
        query: Query | None = {"per_page": 100, **(params or {})}
        while url is not None:
            response = self.request("GET", url, params=query)
            if response.status_code != 200:
                raise _error("GET", path, response)
            page = response.json()
            if not isinstance(page, list):
                raise GitHubAPIError(f"GET {path} returned an unexpected payload", 200)
            items.extend(page)
            url = response.links.get("next", {}).get("url")
            query = None
        return items


def workflow_action_refs(document: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping):
        return refs
    for job in jobs.values():
        if not isinstance(job, Mapping):
            continue
        if isinstance(job.get("uses"), str):
            refs.append(job["uses"])
        for step in job.get("steps") or []:
            if isinstance(step, Mapping) and isinstance(step.get("uses"), str):
                refs.append(step["uses"])
    return refs


def is_pinned(ref: str) -> bool:
    if ref.startswith(("./", "docker://")):
        return True
    _, _, version = ref.partition("@")
    return bool(_FULL_SHA.fullmatch(version))


def declares_permissions(document: Mapping[str, Any]) -> bool:
    if "permissions" in document:
        return True
    jobs = document.get("jobs")
    return (
        isinstance(jobs, Mapping)
        and bool(jobs)
        and all(isinstance(job, Mapping) and "permissions" in job for job in jobs.values())
    )


def analyse_workflow(text: str) -> tuple[list[str], bool]:
    """Return the unpinned action references and whether token permissions are declared."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        return ["<unparseable workflow>"], False
    if not isinstance(document, Mapping):
        return ["<unparseable workflow>"], False
    unpinned = [ref for ref in workflow_action_refs(document) if not is_pinned(ref)]
    return unpinned, declares_permissions(document)


class GitHubCollector:
    name = "github"

    def __init__(self, client: GitHubClient, repositories: Sequence[str]) -> None:
        self._client = client
        self._repositories = list(repositories)

    @property
    def targets(self) -> list[str]:
        return [f"github:{repository}" for repository in self._repositories]

    def collect(self) -> Collection:
        resources: list[Resource] = []
        errors: list[str] = []
        for full_name in self._repositories:
            try:
                resources.append(self._repository(full_name))
            except GitHubAPIError as exc:
                errors.append(f"github:{full_name}: {exc}")
        return Collection(resources, errors)

    def _repository(self, full_name: str) -> Resource:
        owner, repo = full_name.split("/", 1)
        base = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        _, info = self._client.get_json(base)
        branch = str(info.get("default_branch") or "main")
        paths, empty = self._tree(base, branch)
        unavailable: dict[str, str] = {}
        attributes: dict[str, Any] = {
            "full_name": info.get("full_name", full_name),
            "visibility": info.get("visibility")
            or ("private" if info.get("private") else "public"),
            "archived": bool(info.get("archived")),
            "empty": empty,
            "default_branch": branch,
            "license": (info.get("license") or {}).get("spdx_id"),
            "branch_protection": self._branch_protection(base, branch, empty),
            "files": {
                "security_policy": any(path in paths for path in SECURITY_POLICY_PATHS),
                "codeowners": any(path in paths for path in CODEOWNERS_PATHS),
                "dependabot_config": any(path in paths for path in DEPENDABOT_PATHS),
                "readme": any(
                    path.lower().startswith("readme") for path in paths if "/" not in path
                ),
            },
            "workflows": self._workflows(base, branch, paths),
        }
        admin = bool((info.get("permissions") or {}).get("admin"))
        if admin and isinstance(info.get("security_and_analysis"), dict):
            analysis = info["security_and_analysis"]
            attributes["security_and_analysis"] = {
                key: (analysis.get(key) or {}).get("status", "disabled")
                for key in (
                    "secret_scanning",
                    "secret_scanning_push_protection",
                    "dependabot_security_updates",
                )
            }
        else:
            unavailable["security_and_analysis"] = ADMIN_REASON
        if admin:
            attributes["vulnerability_alerts"] = self._vulnerability_alerts(base)
            actions = self._actions_permissions(base)
            if actions is None:
                unavailable["actions"] = ADMIN_REASON
            else:
                attributes["actions"] = actions
        else:
            unavailable["vulnerability_alerts"] = ADMIN_REASON
            unavailable["actions"] = ADMIN_REASON
        return Resource(
            id=f"github:{full_name}",
            type="github.repository",
            name=full_name,
            provider="github",
            source="github-api",
            attributes=attributes,
            unavailable=unavailable,
            url=info.get("html_url"),
        )

    def _tree(self, base: str, branch: str) -> tuple[set[str], bool]:
        status, tree = self._client.get_json(
            f"{base}/git/trees/{quote(branch, safe='')}",
            params={"recursive": "1"},
            allow=(404, 409),
        )
        if status != 200:
            return set(), True
        return {
            str(entry["path"])
            for entry in tree.get("tree", [])
            if isinstance(entry, dict) and entry.get("type") == "blob"
        }, False

    def _branch_protection(self, base: str, branch: str, empty: bool) -> dict[str, Any]:
        if empty:
            return {"protected": False, "rules": []}
        encoded = quote(branch, safe="")
        rules = self._client.paginate(f"{base}/rules/branches/{encoded}")
        _, details = self._client.get_json(f"{base}/branches/{encoded}", allow=(404,))
        return {
            "protected": bool(details and details.get("protected")),
            "rules": sorted(
                {str(rule["type"]) for rule in rules if isinstance(rule, dict) and rule.get("type")}
            ),
        }

    def _file_text(self, base: str, path: str, ref: str) -> str | None:
        status, body = self._client.get_json(
            f"{base}/contents/{quote(path, safe='/')}", params={"ref": ref}, allow=(404,)
        )
        if status != 200 or not isinstance(body, dict) or body.get("encoding") != "base64":
            return None
        return base64.b64decode(body.get("content", "")).decode("utf-8", errors="replace")

    def _workflows(self, base: str, branch: str, paths: set[str]) -> dict[str, Any]:
        files = sorted(
            path
            for path in paths
            if path.startswith(".github/workflows/")
            and path.count("/") == 2
            and path.endswith((".yml", ".yaml"))
        )
        unpinned: list[str] = []
        missing_permissions: list[str] = []
        for path in files:
            text = self._file_text(base, path, branch)
            if text is None:
                continue
            refs, declared = analyse_workflow(text)
            unpinned.extend(f"{path}: {ref}" for ref in refs)
            if not declared:
                missing_permissions.append(path)
        return {
            "files": files,
            "count": len(files),
            "unpinned_actions": unpinned,
            "unpinned_count": len(unpinned),
            "missing_permissions": missing_permissions,
            "missing_permissions_count": len(missing_permissions),
        }

    def _vulnerability_alerts(self, base: str) -> bool:
        status = self._client.status(f"{base}/vulnerability-alerts")
        if status not in (204, 404):
            raise GitHubAPIError(f"GET {base}/vulnerability-alerts returned HTTP {status}", status)
        return status == 204

    def _actions_permissions(self, base: str) -> dict[str, Any] | None:
        status, body = self._client.get_json(
            f"{base}/actions/permissions/workflow", allow=(403, 404)
        )
        if status != 200 or not isinstance(body, dict):
            return None
        return {
            "default_workflow_permissions": body.get("default_workflow_permissions"),
            "can_approve_pull_request_reviews": body.get("can_approve_pull_request_reviews"),
        }
