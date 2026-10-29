"""Load YAML policies and evaluate them against collected resources."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from govflow.expressions import (
    Expression,
    PolicyError,
    parse_expression,
    resolve_path,
    unavailable_reason,
)
from govflow.models import RESOURCE_TYPES, Finding, Resource, Severity, Status
from govflow.util import format_validation_error


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str
    control: str
    url: str | None = Field(default=None, pattern=r"^https://")


class Remediation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    steps: list[str] = Field(min_length=1)
    action: str | None = None
    params: dict[str, str] = Field(default_factory=dict)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Z]{2,5}-\d{3}$")
    title: str = Field(min_length=5, max_length=120)
    resource: str
    severity: Severity
    rationale: str
    check: dict[str, Any]
    remediation: Remediation
    references: list[Reference] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class CompiledPolicy:
    policy: Policy
    expression: Expression
    source: str

    @property
    def id(self) -> str:
        return self.policy.id


def compile_policy(text: str, source: str) -> CompiledPolicy:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"{source}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"{source}: expected a mapping at the top level")
    try:
        policy = Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"{source}: {format_validation_error(exc)}") from exc
    if policy.resource not in RESOURCE_TYPES:
        raise PolicyError(f"{source}: unknown resource type {policy.resource!r}")
    return CompiledPolicy(policy, parse_expression(policy.check, f"{source}: check"), source)


def _builtin_files() -> Iterable[tuple[Traversable, str]]:
    root = files("govflow") / "policies"
    for group in sorted(root.iterdir(), key=lambda item: item.name):
        if not group.is_dir():
            continue
        for item in sorted(group.iterdir(), key=lambda entry: entry.name):
            if item.name.endswith(".yaml"):
                yield item, f"builtin:{group.name}/{item.name}"


def load_policies(
    extra_dirs: Sequence[Path] = (), *, include_builtin: bool = True
) -> list[CompiledPolicy]:
    compiled: list[CompiledPolicy] = []
    if include_builtin:
        for resource, source in _builtin_files():
            compiled.append(compile_policy(resource.read_text(encoding="utf-8"), source))
    for directory in extra_dirs:
        if not directory.is_dir():
            raise PolicyError(f"policy directory {directory} does not exist")
        for path in sorted(directory.rglob("*.yaml")):
            compiled.append(compile_policy(path.read_text(encoding="utf-8"), str(path)))
    seen: dict[str, str] = {}
    for policy in compiled:
        if policy.id in seen:
            raise PolicyError(
                f"duplicate policy id {policy.id} in {policy.source} and {seen[policy.id]}"
            )
        seen[policy.id] = policy.source
    return sorted(compiled, key=lambda policy: policy.id)


def _not_assessed_detail(compiled: CompiledPolicy, resource: Resource) -> str:
    reasons = []
    for path in compiled.expression.paths():
        reason = unavailable_reason(path, resource.unavailable)
        if reason is not None:
            reasons.append(f"{path} {reason}")
    return "Not assessed: " + ("; ".join(reasons) or "required data was unavailable") + "."


def _evidence(compiled: CompiledPolicy, resource: Resource) -> dict[str, Any]:
    evidence: dict[str, Any] = {}
    for path in compiled.expression.paths():
        reason = unavailable_reason(path, resource.unavailable)
        evidence[path] = (
            f"unavailable: {reason}" if reason else resolve_path(resource.attributes, path)
        )
    return evidence


def evaluate(resources: Sequence[Resource], policies: Sequence[CompiledPolicy]) -> list[Finding]:
    findings: list[Finding] = []
    for compiled in policies:
        policy = compiled.policy
        for resource in resources:
            if resource.type != policy.resource:
                continue
            outcome = compiled.expression.evaluate(resource.attributes, resource.unavailable)
            if outcome is None:
                status, detail = Status.NOT_ASSESSED, _not_assessed_detail(compiled, resource)
            elif outcome:
                status, detail = Status.PASS, "Compliant."
            else:
                status, detail = Status.FAIL, f"Not met: {policy.title}."
            findings.append(
                Finding(
                    policy_id=policy.id,
                    policy_title=policy.title,
                    severity=policy.severity,
                    resource_id=resource.id,
                    resource_name=resource.name,
                    resource_type=resource.type,
                    status=status,
                    detail=detail,
                    evidence=_evidence(compiled, resource),
                )
            )
    return findings


def summarize(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {status.value: 0 for status in Status}
    for finding in findings:
        counts[finding.status.value] += 1
    return counts


def failed_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity.value: 0 for severity in Severity}
    for finding in findings:
        if finding.status is Status.FAIL:
            counts[finding.severity.value] += 1
    return counts


def compliance_score(findings: Sequence[Finding]) -> float | None:
    """Share of assessed checks that passed; not-assessed checks are excluded."""
    assessed = [finding for finding in findings if finding.status is not Status.NOT_ASSESSED]
    if not assessed:
        return None
    passed = sum(1 for finding in assessed if finding.status is Status.PASS)
    return round(100 * passed / len(assessed), 1)


def exceeds_threshold(findings: Iterable[Finding], threshold: Severity) -> bool:
    return any(
        finding.status is Status.FAIL and finding.severity.rank >= threshold.rank
        for finding in findings
    )
