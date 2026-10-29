"""Append-only, hash-chained audit log stored as JSON Lines.

Every entry stores the hash of the previous entry, so editing, deleting or
reordering any line breaks the chain and is detected by ``verify``. A run's
first entry can point at the last hash of the previous run, linking runs.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from govflow.util import canonical_json, isoformat, sha256_hex, utcnow

GENESIS = "0" * 64


class AuditEvent(BaseModel):
    seq: int
    ts: str
    run_id: str
    actor: str
    event: str
    data: dict[str, Any]
    prev_hash: str
    hash: str


@dataclass(frozen=True)
class Verification:
    ok: bool
    count: int
    genesis: str
    head: str
    error: str | None = None


def entry_hash(entry: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json({key: value for key, value in entry.items() if key != "hash"}))


class AuditLog:
    def __init__(
        self,
        path: Path,
        run_id: str,
        *,
        genesis: str = GENESIS,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.path = path
        self.run_id = run_id
        self._clock = clock
        self._seq = 0
        self._head = genesis
        events = read_events(path) if path.exists() else []
        if events:
            self._seq, self._head = events[-1].seq, events[-1].hash

    @property
    def head(self) -> str:
        return self._head

    def append(self, actor: str, event: str, data: Mapping[str, Any] | None = None) -> AuditEvent:
        entry: dict[str, Any] = {
            "seq": self._seq + 1,
            "ts": isoformat(self._clock()),
            "run_id": self.run_id,
            "actor": actor,
            "event": event,
            # Round-trip through JSON so the stored form hashes exactly like the original.
            "data": json.loads(canonical_json(dict(data or {}))),
            "prev_hash": self._head,
        }
        entry["hash"] = entry_hash(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json(entry) + "\n")
        self._seq += 1
        self._head = entry["hash"]
        return AuditEvent.model_validate(entry)


def read_events(path: Path) -> list[AuditEvent]:
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(AuditEvent.model_validate_json(line))
    return events


def verify(path: Path, genesis: str | None = GENESIS) -> Verification:
    """Check every link of the chain; ``genesis=None`` accepts the first entry's prev_hash."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return Verification(
            False, 0, genesis or "", genesis or "", f"cannot read {path.name}: {exc}"
        )
    expected_prev = genesis
    start = genesis
    count = 0
    for number, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
            event = AuditEvent.model_validate(entry)
        except (json.JSONDecodeError, ValidationError):
            return _broken(start, count, expected_prev, f"line {number} is not a valid audit event")
        if expected_prev is None:
            expected_prev = start = event.prev_hash
        if event.seq != count + 1:
            return _broken(start, count, expected_prev, f"line {number}: expected seq {count + 1}")
        if event.prev_hash != expected_prev:
            return _broken(start, count, expected_prev, f"line {number}: chain link is broken")
        if entry_hash(entry) != event.hash:
            return _broken(start, count, expected_prev, f"line {number}: entry was modified")
        expected_prev = event.hash
        count += 1
    if count == 0:
        return _broken(start, 0, expected_prev, "audit log is empty")
    return Verification(True, count, start or "", expected_prev or "")


def _broken(start: str | None, count: int, head: str | None, error: str) -> Verification:
    return Verification(False, count, start or "", head or "", error)
