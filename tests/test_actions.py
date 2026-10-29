from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import pytest

from govflow.actions.base import ActionError, ChangeContext, describe_action, render_file
from govflow.actions.github_pr import GitHubPullRequestExecutor
from govflow.connectors.github import GitHubClient
from govflow.models import PlannedAction

CONTEXT = ChangeContext("CR-run-A1-1", "run", "d" * 64, "approver")


def _action(**overrides: Any) -> PlannedAction:
    data: dict[str, Any] = {
        "id": "A1",
        "action": "github.add_file",
        "target": "github:acme/app",
        "policy_id": "GH-002",
        "params": {"path": "SECURITY.md", "template": "security_md"},
        "summary": "Remediate GH-002 on acme/app",
        "allowed": True,
    }
    data.update(overrides)
    return PlannedAction.model_validate(data)


class FakeGitHub:
    def __init__(self, existing: bool = False) -> None:
        self.existing = existing
        self.calls: list[tuple[str, str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, body))
        path = request.url.path
        if request.method == "GET" and path == "/repos/acme/app":
            return httpx.Response(200, json={"default_branch": "main"})
        if request.method == "GET" and path == "/repos/acme/app/contents/SECURITY.md":
            return httpx.Response(200 if self.existing else 404, json={})
        if request.method == "GET" and path == "/repos/acme/app/git/ref/heads/main":
            return httpx.Response(200, json={"object": {"sha": "abc123"}})
        if request.method == "POST" and path == "/repos/acme/app/git/refs":
            return httpx.Response(201, json={})
        if request.method == "PUT":
            return httpx.Response(201, json={})
        if request.method == "POST" and path == "/repos/acme/app/pulls":
            return httpx.Response(201, json={"html_url": "https://github.com/acme/app/pull/7"})
        return httpx.Response(500, json={"message": "unexpected"})


def test_opens_pull_request_with_file_and_change_record() -> None:
    fake = FakeGitHub()
    with GitHubClient("token", transport=httpx.MockTransport(fake)) as client:
        status, result = GitHubPullRequestExecutor(client).execute(_action(), CONTEXT)
    assert (status, result) == ("applied", "opened pull request https://github.com/acme/app/pull/7")
    puts = [call for call in fake.calls if call[0] == "PUT"]
    assert [call[1] for call in puts] == [
        "/repos/acme/app/contents/SECURITY.md",
        "/repos/acme/app/contents/docs/governance/changes/CR-run-A1-1.md",
    ]
    assert all(call[2]["branch"] == "govflow/run/a1" for call in puts)
    security = base64.b64decode(puts[0][2]["content"]).decode()
    assert "https://github.com/acme/app/security/advisories/new" in security
    pull = next(call for call in fake.calls if call[1].endswith("/pulls"))
    assert pull[2]["base"] == "main"
    assert "Plan digest" in pull[2]["body"]
    assert "approver" in pull[2]["body"]


def test_existing_file_is_skipped() -> None:
    fake = FakeGitHub(existing=True)
    with GitHubClient("token", transport=httpx.MockTransport(fake)) as client:
        status, result = GitHubPullRequestExecutor(client).execute(_action(), CONTEXT)
    assert status == "skipped"
    assert "already exists" in result
    assert not [call for call in fake.calls if call[0] in ("POST", "PUT")]


@pytest.mark.parametrize(
    ("action", "message"),
    [
        (_action(action="aws.delete_bucket"), "not supported"),
        (_action(target="aws:1:bucket"), "not supported"),
        (_action(params={"path": "SECURITY.md"}), "needs 'path' and 'template'"),
    ],
)
def test_invalid_actions_are_rejected(action: PlannedAction, message: str) -> None:
    with (
        GitHubClient("token", transport=httpx.MockTransport(FakeGitHub())) as client,
        pytest.raises(ActionError, match=message),
    ):
        GitHubPullRequestExecutor(client).execute(action, CONTEXT)


def test_api_failures_become_action_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"message": "Resource not accessible by integration"})

    with (
        GitHubClient("token", transport=httpx.MockTransport(handler)) as client,
        pytest.raises(ActionError, match="Resource not accessible"),
    ):
        GitHubPullRequestExecutor(client).execute(_action(), CONTEXT)


def test_templates_and_descriptions() -> None:
    assert render_file("codeowners", owner="acme").strip().endswith("* @acme")
    assert "run-9" in render_file("canary", run_id="run-9", change_id="CR-1")
    with pytest.raises(ActionError, match="unknown file template"):
        render_file("nope")
    assert describe_action(_action()) == "open a pull request on acme/app that adds SECURITY.md"
    assert describe_action(_action(action="x.y", target="t")) == "x.y on t"
