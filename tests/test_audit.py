from __future__ import annotations

import json
from pathlib import Path

from govflow.audit import GENESIS, AuditLog, read_events, verify
from tests.conftest import Clock


def _log(path: Path, events: int = 3, genesis: str = GENESIS) -> AuditLog:
    log = AuditLog(path, "run-1", genesis=genesis, clock=Clock())
    for index in range(events):
        log.append("alice", f"event.{index}", {"index": index, "nested": {"b": 2, "a": 1}})
    return log


def test_chain_verifies(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = _log(path)
    result = verify(path)
    assert result.ok
    assert result.count == 3
    assert result.genesis == GENESIS
    assert result.head == log.head
    assert [event.seq for event in read_events(path)] == [1, 2, 3]


def test_reopening_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _log(path, events=2)
    resumed = AuditLog(path, "run-1", clock=Clock())
    event = resumed.append("bob", "event.later")
    assert event.seq == 3
    assert verify(path).ok


def test_modified_entry_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _log(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["actor"] = "mallory"
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify(path)
    assert not result.ok
    assert result.error == "line 2: entry was modified"
    assert result.count == 1


def test_deleted_and_reordered_entries_are_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _log(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    assert verify(path).error == "line 2: expected seq 2"
    path.write_text("\n".join([lines[1], lines[0]]) + "\n", encoding="utf-8")
    assert verify(path).error == "line 1: expected seq 1"


def test_broken_link_and_wrong_genesis(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _log(path, genesis="a" * 64)
    assert verify(path).error == "line 1: chain link is broken"
    assert verify(path, genesis="a" * 64).ok
    lenient = verify(path, genesis=None)
    assert lenient.ok
    assert lenient.genesis == "a" * 64


def test_garbage_empty_and_missing_logs(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    assert verify(path).error == "line 1 is not a valid audit event"
    path.write_text("", encoding="utf-8")
    assert verify(path).error == "audit log is empty"
    missing = verify(tmp_path / "nope.jsonl")
    assert not missing.ok
    assert missing.error is not None
    assert "cannot read" in missing.error
