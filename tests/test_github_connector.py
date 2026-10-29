from __future__ import annotations

from typing import Any

import httpx
import pytest

from govflow.connectors.github import (
    ADMIN_REASON,
    GitHubAPIError,
    GitHubClient,
    GitHubCollector,
    analyse_workflow,
    is_pinned,
)

TOKEN = "ghp_supersecretvalue1234567890"


def test_demo_repositories_are_described(demo_client: GitHubClient) -> None:
    collection = GitHubCollector(
        demo_client, ["acme-demo/payments-api", "acme-demo/docs-site", "acme-demo/legacy-tools"]
    ).collect()
    assert collection.errors == []
    payments, docs, legacy = collection.resources
    workflows = payments.attributes["workflows"]
    assert workflows["unpinned_actions"] == [
        ".github/workflows/ci.yml: actions/checkout@v4",
        ".github/workflows/ci.yml: actions/setup-python@v5",
    ]
    assert workflows["missing_permissions"] == [".github/workflows/ci.yml"]
    assert payments.attributes["vulnerability_alerts"] is False
    assert payments.attributes["actions"]["default_workflow_permissions"] == "write"
    assert payments.attributes["security_and_analysis"]["secret_scanning"] == "disabled"
    assert payments.unavailable == {}
    assert docs.attributes["branch_protection"] == {
        "protected": True,
        "rules": ["deletion", "non_fast_forward", "pull_request"],
    }
    assert docs.attributes["files"] == {
        "security_policy": True,
        "codeowners": True,
        "dependabot_config": True,
        "readme": True,
    }
    assert docs.attributes["workflows"]["unpinned_count"] == 0
    assert docs.unavailable == {
        "security_and_analysis": ADMIN_REASON,
        "vulnerability_alerts": ADMIN_REASON,
        "actions": ADMIN_REASON,
    }
    assert legacy.attributes["license"] is None
    assert legacy.url == "https://github.com/acme-demo/legacy-tools"


def _client(handler: Any, **kwargs: Any) -> GitHubClient:
    return GitHubClient(TOKEN, transport=httpx.MockTransport(handler), **kwargs)


def test_pagination_follows_link_headers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json=[{"type": "deletion"}])
        link = '<https://api.github.com/items?page=2>; rel="next"'
        return httpx.Response(200, json=[{"type": "pull_request"}], headers={"link": link})

    with _client(handler) as client:
        assert client.paginate("/items") == [{"type": "pull_request"}, {"type": "deletion"}]


def test_rate_limit_waits_for_reset_then_retries() -> None:
    responses = iter(
        [
            httpx.Response(
                403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1010"}
            ),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    waits: list[float] = []
    with _client(lambda request: next(responses), sleep=waits.append, now=lambda: 1000.0) as client:
        assert client.get_json("/rate") == (200, {"ok": True})
    assert waits == [11.0]


def test_rate_limit_beyond_max_wait_is_reported() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"retry-after": "3600", "x-ratelimit-remaining": "0"})

    with (
        _client(handler, sleep=lambda seconds: None) as client,
        pytest.raises(GitHubAPIError, match="rate limit exhausted"),
    ):
        client.get_json("/slow")


def test_secondary_rate_limit_retry_after_is_honoured() -> None:
    responses = iter(
        [httpx.Response(403, headers={"retry-after": "2"}), httpx.Response(200, json=[])]
    )
    waits: list[float] = []
    with _client(lambda request: next(responses), sleep=waits.append) as client:
        assert client.get_json("/secondary") == (200, [])
    assert waits == [2.0]


def test_errors_and_repr_never_leak_the_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        return httpx.Response(401, json={"message": "Bad credentials"})

    with _client(handler) as client:
        with pytest.raises(GitHubAPIError) as caught:
            client.get_json("/repos/acme/app")
        assert TOKEN not in str(caught.value)
        assert "authentication failed" in str(caught.value)
        assert TOKEN not in repr(client)


def test_network_errors_are_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    with _client(handler) as client, pytest.raises(GitHubAPIError, match="ConnectError"):
        client.get_json("/down")


def test_api_message_is_included_and_payload_checked() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/list":
            return httpx.Response(200, json={"not": "a list"})
        return httpx.Response(422, json={"message": "Validation Failed"})

    with _client(handler) as client:
        with pytest.raises(GitHubAPIError, match="Validation Failed"):
            client.send_json("POST", "/things", {"a": 1})
        with pytest.raises(GitHubAPIError, match="unexpected payload"):
            client.paginate("/list")


def test_missing_repository_is_reported_not_raised() -> None:
    with _client(lambda request: httpx.Response(404, json={"message": "Not Found"})) as client:
        collection = GitHubCollector(client, ["acme/missing"]).collect()
    assert collection.resources == []
    assert collection.errors == [
        "github:acme/missing: GET /repos/acme/missing returned HTTP 404: Not Found"
    ]


def test_empty_repository_and_admin_without_actions_permission() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/repos/acme/empty":
            return httpx.Response(
                200, json={"default_branch": "main", "permissions": {"admin": True}}
            )
        if path.endswith("/git/trees/main"):
            return httpx.Response(409, json={"message": "Git Repository is empty."})
        if path.endswith("/vulnerability-alerts"):
            return httpx.Response(204)
        return httpx.Response(403, json={"message": "Resource not accessible"})

    with _client(handler) as client:
        collection = GitHubCollector(client, ["acme/empty"]).collect()
    resource = collection.resources[0]
    assert resource.attributes["empty"] is True
    assert resource.attributes["branch_protection"] == {"protected": False, "rules": []}
    assert resource.attributes["vulnerability_alerts"] is True
    assert set(resource.unavailable) == {"security_and_analysis", "actions"}


def test_unexpected_vulnerability_alert_status_is_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/repos/acme/app":
            return httpx.Response(200, json={"permissions": {"admin": True}})
        if request.url.path.endswith("/vulnerability-alerts"):
            return httpx.Response(500)
        return httpx.Response(409)

    with _client(handler) as client:
        collection = GitHubCollector(client, ["acme/app"]).collect()
    assert "vulnerability-alerts returned HTTP 500" in collection.errors[0]


@pytest.mark.parametrize(
    ("text", "unpinned", "declared"),
    [
        ("jobs: [", ["<unparseable workflow>"], False),
        ("- a list", ["<unparseable workflow>"], False),
        ("name: x", [], False),
        (
            "jobs:\n  a:\n    permissions: {}\n    uses: org/repo/.github/workflows/w.yml@main\n",
            ["org/repo/.github/workflows/w.yml@main"],
            True,
        ),
        (
            "permissions: {}\njobs:\n  b:\n    steps:\n      - uses: ./local\n"
            "      - uses: docker://alpine:3\n      - run: echo\n",
            [],
            True,
        ),
    ],
)
def test_workflow_analysis(text: str, unpinned: list[str], declared: bool) -> None:
    assert analyse_workflow(text) == (unpinned, declared)


def test_pin_detection() -> None:
    assert is_pinned("actions/checkout@" + "a" * 40)
    assert not is_pinned("actions/checkout@v4")
    assert not is_pinned("actions/checkout")
