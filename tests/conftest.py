from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from govflow.config import Config, parse_config_text
from govflow.connectors.base import Connector
from govflow.connectors.fixtures import fixture_transport
from govflow.connectors.github import GitHubClient, GitHubCollector
from govflow.connectors.snapshots import SnapshotConnector
from govflow.policy_engine import CompiledPolicy, load_policies
from govflow.workflow import Run, scan

RUN_ID = "20261029T090000Z-test01"


def demo_text(name: str) -> str:
    return (files("govflow") / "demo_data" / name).read_text(encoding="utf-8")


class Clock:
    """Deterministic clock that advances one second per call."""

    def __init__(self) -> None:
        self.now = datetime(2026, 10, 29, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture(scope="session")
def policies() -> list[CompiledPolicy]:
    return load_policies()


@pytest.fixture
def demo_config() -> Config:
    return parse_config_text(demo_text("govflow.demo.yaml"), "demo config")


@pytest.fixture
def demo_routes() -> dict[str, Any]:
    routes: dict[str, Any] = json.loads(demo_text("github_api.json"))
    return routes


@pytest.fixture
def demo_client(demo_routes: dict[str, Any]) -> Iterator[GitHubClient]:
    with GitHubClient(transport=fixture_transport(demo_routes)) as client:
        yield client


@pytest.fixture
def demo_connectors(demo_client: GitHubClient, demo_config: Config) -> list[Connector]:
    return [
        GitHubCollector(demo_client, demo_config.targets.github.repositories),
        SnapshotConnector(demo_text("aws_snapshot.json"), "aws_snapshot.json"),
        SnapshotConnector(demo_text("gcp_snapshot.json"), "gcp_snapshot.json"),
    ]


@pytest.fixture
def demo_run(
    tmp_path: Path,
    demo_config: Config,
    demo_connectors: list[Connector],
    policies: list[CompiledPolicy],
    clock: Clock,
) -> Run:
    return scan(
        demo_config,
        demo_connectors,
        policies,
        tmp_path / "runs",
        actor="requester",
        clock=clock,
        run_id=RUN_ID,
    )
