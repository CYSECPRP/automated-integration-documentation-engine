"""Common connector interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from govflow.models import Resource


class CollectionError(RuntimeError):
    """A connector could not run at all (individual target failures are reported as errors)."""


@dataclass(frozen=True)
class Collection:
    resources: list[Resource] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class Connector(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def targets(self) -> list[str]: ...

    def collect(self) -> Collection: ...
