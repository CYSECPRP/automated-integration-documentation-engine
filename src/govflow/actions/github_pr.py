"""Apply github.add_file by opening a pull request; never push to the default branch."""

from __future__ import annotations

import base64
from urllib.parse import quote

from govflow.actions.base import ActionError, ChangeContext, describe_action, render_file
from govflow.connectors.github import GitHubAPIError, GitHubClient
from govflow.docs_engine import change_record_markdown
from govflow.models import ChangeStatus, PlannedAction


class GitHubPullRequestExecutor:
    def __init__(self, client: GitHubClient) -> None:
        self._client = client

    def describe(self, action: PlannedAction) -> str:
        return describe_action(action)

    def execute(self, action: PlannedAction, context: ChangeContext) -> tuple[ChangeStatus, str]:
        if action.action != "github.add_file" or not action.target.startswith("github:"):
            raise ActionError(f"{action.action} on {action.target} is not supported")
        try:
            return self._add_file(action, context)
        except GitHubAPIError as exc:
            raise ActionError(str(exc)) from exc

    def _put(self, base: str, path: str, text: str, branch: str, message: str) -> None:
        payload = {
            "message": message,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
            "branch": branch,
        }
        self._client.send_json("PUT", f"{base}/contents/{quote(path, safe='/')}", payload)

    def _add_file(self, action: PlannedAction, context: ChangeContext) -> tuple[ChangeStatus, str]:
        path = action.params.get("path")
        template = action.params.get("template")
        if not path or not template:
            raise ActionError("github.add_file needs 'path' and 'template' parameters")
        owner, repo = action.target.removeprefix("github:").split("/", 1)
        base = f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"
        _, info = self._client.get_json(base)
        default_branch = str(info.get("default_branch") or "main")
        status, _ = self._client.get_json(
            f"{base}/contents/{quote(path, safe='/')}", params={"ref": default_branch}, allow=(404,)
        )
        if status == 200:
            return "skipped", f"{path} already exists on {default_branch}; nothing to change"
        content = render_file(
            template, owner=owner, repo=repo, run_id=context.run_id, change_id=context.change_id
        )
        _, ref = self._client.get_json(f"{base}/git/ref/heads/{quote(default_branch, safe='')}")
        branch = f"govflow/{context.run_id}/{action.id.lower()}"
        self._client.send_json(
            "POST",
            f"{base}/git/refs",
            {"ref": f"refs/heads/{branch}", "sha": ref["object"]["sha"]},
            expected=(201,),
        )
        self._put(
            base, path, content, branch, f"{action.policy_id}: add {path} ({context.change_id})"
        )
        record = change_record_markdown(action, context, description=describe_action(action))
        self._put(
            base,
            f"docs/governance/changes/{context.change_id}.md",
            record,
            branch,
            f"Change record {context.change_id}",
        )
        pull = self._client.send_json(
            "POST",
            f"{base}/pulls",
            {
                "title": f"[govflow] {action.policy_id}: add {path}",
                "head": branch,
                "base": default_branch,
                "body": record,
            },
            expected=(201,),
        )
        return "applied", f"opened pull request {pull['html_url']}"
