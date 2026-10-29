"""Core data model shared by every stage of the pipeline."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from govflow.util import canonical_json, sha256_hex

RESOURCE_TYPES = frozenset(
    {
        "github.repository",
        "aws.s3.bucket",
        "aws.ec2.security_group",
        "aws.iam.account",
        "gcp.storage.bucket",
        "gcp.compute.firewall",
    }
)


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


class Status(StrEnum):
    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    NOT_ASSESSED = "not_assessed"


class Resource(BaseModel):
    """Something collected from an integration, described by plain attributes."""

    model_config = ConfigDict(frozen=True)

    id: str
    type: str
    name: str
    provider: str
    source: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    # attribute path -> why it could not be collected (e.g. missing permission)
    unavailable: dict[str, str] = Field(default_factory=dict)
    url: str | None = None


class Finding(BaseModel):
    policy_id: str
    policy_title: str
    severity: Severity
    resource_id: str
    resource_name: str
    resource_type: str
    status: Status
    detail: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class PlannedAction(BaseModel):
    id: str
    action: str
    target: str
    policy_id: str
    params: dict[str, str] = Field(default_factory=dict)
    summary: str
    allowed: bool
    blocked_reason: str | None = None


class Plan(BaseModel):
    run_id: str
    created_at: datetime
    actions: list[PlannedAction] = Field(default_factory=list)

    @property
    def digest(self) -> str:
        """Fingerprint of exactly what would be done; approvals are bound to it."""
        payload = {
            "run_id": self.run_id,
            "actions": [action.model_dump(mode="json") for action in self.actions],
        }
        return sha256_hex(canonical_json(payload))

    @property
    def executable(self) -> list[PlannedAction]:
        return [action for action in self.actions if action.allowed]


class Approval(BaseModel):
    run_id: str
    plan_digest: str
    approver: str
    approved_at: datetime
    comment: str = ""


ChangeStatus = Literal["dry-run", "simulated", "applied", "skipped", "failed"]


class ChangeRecord(BaseModel):
    id: str
    run_id: str
    action: PlannedAction
    status: ChangeStatus
    result: str
    approver: str | None = None
    plan_digest: str
    recorded_at: datetime


class RunInfo(BaseModel):
    run_id: str
    name: str
    actor: str
    started_at: datetime
    finished_at: datetime
    engine_version: str
    config_digest: str
    targets: list[str]
    policy_count: int
    resource_count: int
    counts: dict[str, int]
    collection_errors: list[str] = Field(default_factory=list)
    plan_digest: str
    audit_genesis: str
