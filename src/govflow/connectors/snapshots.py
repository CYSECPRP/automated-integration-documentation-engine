"""Offline cloud configuration snapshots in a documented, normalised JSON format."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from govflow.connectors.base import Collection, CollectionError
from govflow.models import Resource
from govflow.util import format_validation_error

SNAPSHOT_FORMAT = "govflow-snapshot/v1"
PROVIDER_TYPES = {
    "aws": frozenset({"aws.s3.bucket", "aws.ec2.security_group", "aws.iam.account"}),
    "gcp": frozenset({"gcp.storage.bucket", "gcp.compute.firewall"}),
}


class SnapshotResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: str
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    attributes: dict[str, Any] = Field(default_factory=dict)


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: Literal["govflow-snapshot/v1"]
    provider: Literal["aws", "gcp"]
    scope: str = Field(min_length=1)
    collected_at: datetime
    resources: list[SnapshotResource]

    @model_validator(mode="after")
    def _types_and_ids(self) -> Snapshot:
        allowed = PROVIDER_TYPES[self.provider]
        seen: set[str] = set()
        for resource in self.resources:
            if resource.type not in allowed:
                raise ValueError(
                    f"resource type {resource.type!r} is not valid for {self.provider}"
                )
            key = f"{resource.type}:{resource.id}"
            if key in seen:
                raise ValueError(f"duplicate resource {key}")
            seen.add(key)
        return self


class SnapshotConnector:
    def __init__(self, text: str, label: str) -> None:
        self._text = text
        self._label = label

    @classmethod
    def from_path(cls, path: Path) -> SnapshotConnector:
        try:
            return cls(path.read_text(encoding="utf-8"), path.name)
        except OSError as exc:
            raise CollectionError(f"snapshot {path}: {exc.strerror or exc}") from exc

    @property
    def name(self) -> str:
        return f"snapshot:{self._label}"

    @property
    def targets(self) -> list[str]:
        return [self.name]

    def collect(self) -> Collection:
        try:
            snapshot = Snapshot.model_validate(json.loads(self._text))
        except json.JSONDecodeError as exc:
            return Collection(errors=[f"{self.name}: invalid JSON ({exc.msg})"])
        except ValidationError as exc:
            return Collection(errors=[f"{self.name}: {format_validation_error(exc)}"])
        resources = [
            Resource(
                id=f"{snapshot.provider}:{snapshot.scope}:{item.id}",
                type=item.type,
                name=item.name,
                provider=snapshot.provider,
                source=self.name,
                attributes=item.attributes,
            )
            for item in snapshot.resources
        ]
        return Collection(resources)
