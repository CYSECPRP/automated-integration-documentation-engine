from __future__ import annotations

import json
from pathlib import Path

import pytest

from govflow.connectors.base import CollectionError
from govflow.connectors.snapshots import SnapshotConnector
from tests.conftest import demo_text


def test_demo_snapshot_resources() -> None:
    connector = SnapshotConnector(demo_text("aws_snapshot.json"), "aws.json")
    collection = connector.collect()
    assert collection.errors == []
    assert connector.name == "snapshot:aws.json"
    assert connector.targets == ["snapshot:aws.json"]
    assert [resource.id for resource in collection.resources][:2] == [
        "aws:111122223333:acme-public-assets",
        "aws:111122223333:acme-audit-logs",
    ]
    assert {resource.source for resource in collection.resources} == {"snapshot:aws.json"}


def _snapshot(**overrides: object) -> str:
    data: dict[str, object] = {
        "format": "govflow-snapshot/v1",
        "provider": "aws",
        "scope": "1",
        "collected_at": "2026-10-20T09:00:00Z",
        "resources": [{"type": "aws.s3.bucket", "id": "b", "name": "b"}],
    }
    data.update(overrides)
    return json.dumps(data)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("{not json", "invalid JSON"),
        (_snapshot(format="other"), "format"),
        (
            _snapshot(resources=[{"type": "gcp.storage.bucket", "id": "b", "name": "b"}]),
            "not valid for aws",
        ),
        (
            _snapshot(
                resources=[
                    {"type": "aws.s3.bucket", "id": "b", "name": "b"},
                    {"type": "aws.s3.bucket", "id": "b", "name": "b"},
                ]
            ),
            "duplicate resource",
        ),
    ],
)
def test_invalid_snapshots_are_reported(text: str, message: str) -> None:
    collection = SnapshotConnector(text, "bad.json").collect()
    assert collection.resources == []
    assert message in collection.errors[0]


def test_missing_snapshot_file(tmp_path: Path) -> None:
    with pytest.raises(CollectionError, match=r"missing\.json"):
        SnapshotConnector.from_path(tmp_path / "missing.json")
    path = tmp_path / "ok.json"
    path.write_text(_snapshot(), encoding="utf-8")
    assert SnapshotConnector.from_path(path).collect().resources[0].id == "aws:1:b"
