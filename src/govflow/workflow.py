"""Run orchestration: collect -> evaluate -> plan -> approve -> apply, every step audited."""

from __future__ import annotations

import secrets
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from govflow import __version__
from govflow.actions.base import ActionError, ChangeContext, Executor
from govflow.audit import GENESIS, AuditLog, read_events, verify
from govflow.config import Config
from govflow.connectors.base import CollectionError, Connector
from govflow.governance import (
    GovernanceError,
    add_canary,
    approve,
    authorize_execution,
    build_plan,
)
from govflow.models import (
    Approval,
    ChangeRecord,
    ChangeStatus,
    Finding,
    Plan,
    Resource,
    RunInfo,
)
from govflow.policy_engine import CompiledPolicy, evaluate, summarize
from govflow.util import read_json, utcnow, write_json

Clock = Callable[[], datetime]


class RunError(RuntimeError):
    """A run directory is missing, incomplete or was modified after the fact."""


@dataclass
class Run:
    path: Path
    info: RunInfo
    resources: list[Resource]
    findings: list[Finding]
    plan: Plan
    approval: Approval | None = None
    changes: list[ChangeRecord] = field(default_factory=list)

    @property
    def audit_path(self) -> Path:
        return self.path / "audit.jsonl"


def new_run_id(moment: datetime) -> str:
    return f"{moment:%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


def scan(
    config: Config,
    connectors: Sequence[Connector],
    policies: Sequence[CompiledPolicy],
    out_dir: Path,
    *,
    actor: str,
    genesis: str = GENESIS,
    canary: bool = False,
    clock: Clock = utcnow,
    run_id: str | None = None,
) -> Run:
    started = clock()
    run_id = run_id or new_run_id(started)
    run_dir = out_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    audit = AuditLog(run_dir / "audit.jsonl", run_id, genesis=genesis, clock=clock)
    targets = [target for connector in connectors for target in connector.targets]
    audit.append(
        actor,
        "run.started",
        {
            "name": config.name,
            "engine_version": __version__,
            "config_digest": config.digest,
            "policies": len(policies),
            "targets": targets,
        },
    )

    resources: list[Resource] = []
    errors: list[str] = []
    for connector in connectors:
        try:
            collection = connector.collect()
        except CollectionError as exc:
            errors.append(f"{connector.name}: {exc}")
            audit.append(actor, "collect.failed", {"connector": connector.name, "error": str(exc)})
            continue
        resources.extend(collection.resources)
        errors.extend(collection.errors)
        audit.append(
            actor,
            "collect.completed",
            {
                "connector": connector.name,
                "resources": len(collection.resources),
                "errors": collection.errors,
            },
        )

    findings = evaluate(resources, policies)
    counts = summarize(findings)
    audit.append(actor, "evaluate.completed", {"findings": len(findings), **counts})

    plan = build_plan(run_id, findings, policies, config.governance, created_at=clock())
    if canary:
        plan = add_canary(plan, config.governance)
    audit.append(
        actor,
        "plan.created",
        {"digest": plan.digest, "actions": len(plan.actions), "executable": len(plan.executable)},
    )

    info = RunInfo(
        run_id=run_id,
        name=config.name,
        actor=actor,
        started_at=started,
        finished_at=clock(),
        engine_version=__version__,
        config_digest=config.digest,
        targets=targets,
        policy_count=len(policies),
        resource_count=len(resources),
        counts=counts,
        collection_errors=errors,
        plan_digest=plan.digest,
        audit_genesis=genesis,
    )
    write_json(run_dir / "run.json", info.model_dump(mode="json"))
    write_json(run_dir / "resources.json", [item.model_dump(mode="json") for item in resources])
    write_json(run_dir / "findings.json", [item.model_dump(mode="json") for item in findings])
    write_json(run_dir / "plan.json", {**plan.model_dump(mode="json"), "digest": plan.digest})
    audit.append(actor, "run.completed", {"resources": len(resources), "errors": len(errors)})
    return Run(run_dir, info, resources, findings, plan)


def load_run(run_dir: Path, *, verify_integrity: bool = True) -> Run:
    if not (run_dir / "run.json").is_file():
        raise RunError(f"{run_dir} is not a govflow run directory")
    try:
        info = RunInfo.model_validate(read_json(run_dir / "run.json"))
        resources = [
            Resource.model_validate(item) for item in read_json(run_dir / "resources.json")
        ]
        findings = [Finding.model_validate(item) for item in read_json(run_dir / "findings.json")]
        plan = Plan.model_validate(read_json(run_dir / "plan.json"))
        approval_path = run_dir / "approval.json"
        approval = (
            Approval.model_validate(read_json(approval_path)) if approval_path.is_file() else None
        )
        changes_path = run_dir / "changes.json"
        changes = (
            [ChangeRecord.model_validate(item) for item in read_json(changes_path)]
            if changes_path.is_file()
            else []
        )
    except (OSError, ValueError) as exc:
        raise RunError(f"{run_dir}: run files are unreadable: {exc}") from exc
    run = Run(run_dir, info, resources, findings, plan, approval, changes)
    if verify_integrity:
        _check_integrity(run)
    return run


def _check_integrity(run: Run) -> None:
    result = verify(run.audit_path, genesis=run.info.audit_genesis)
    if not result.ok:
        raise RunError(f"audit log failed verification: {result.error}")
    created = [event for event in read_events(run.audit_path) if event.event == "plan.created"]
    if not created or created[-1].data.get("digest") != run.plan.digest:
        raise RunError("plan.json does not match the plan digest recorded in the audit log")


def approve_run(
    run_dir: Path,
    *,
    approver: str,
    digest: str,
    config: Config,
    comment: str = "",
    clock: Clock = utcnow,
) -> Approval:
    run = load_run(run_dir)
    audit = AuditLog(run.audit_path, run.info.run_id, genesis=run.info.audit_genesis, clock=clock)
    try:
        approval = approve(
            run.plan,
            approver=approver,
            digest=digest,
            settings=config.governance,
            requester=run.info.actor,
            approved_at=clock(),
            comment=comment,
        )
    except GovernanceError as exc:
        audit.append(
            approver or "unknown", "approval.rejected", {"digest": digest, "reason": str(exc)}
        )
        raise
    write_json(run_dir / "approval.json", approval.model_dump(mode="json"))
    audit.append(approver, "plan.approved", {"digest": digest, "comment": comment})
    return approval


def apply_run(
    run_dir: Path,
    *,
    config: Config,
    executor: Executor,
    actor: str,
    execute: bool,
    clock: Clock = utcnow,
) -> list[ChangeRecord]:
    run = load_run(run_dir)
    audit = AuditLog(run.audit_path, run.info.run_id, genesis=run.info.audit_genesis, clock=clock)
    if execute:
        try:
            authorize_execution(run.plan, run.approval, config.governance)
        except GovernanceError as exc:
            audit.append(actor, "apply.refused", {"reason": str(exc)})
            raise
    done = {change.action.id for change in run.changes if change.status in ("applied", "simulated")}
    approver = run.approval.approver if run.approval else None
    records = list(run.changes)
    new_records: list[ChangeRecord] = []
    for action in run.plan.actions:
        attempt = sum(1 for change in records if change.action.id == action.id) + 1
        change_id = f"CR-{run.info.run_id}-{action.id}-{attempt}"
        status: ChangeStatus
        if not action.allowed:
            status, result = "skipped", f"blocked by governance: {action.blocked_reason}"
        elif action.id in done:
            status, result = "skipped", "already executed by an earlier apply"
        elif not execute:
            status, result = "dry-run", f"would {executor.describe(action)}"
        else:
            context = ChangeContext(change_id, run.info.run_id, run.plan.digest, approver)
            try:
                status, result = executor.execute(action, context)
            except ActionError as exc:
                status, result = "failed", str(exc)
        record = ChangeRecord(
            id=change_id,
            run_id=run.info.run_id,
            action=action,
            status=status,
            result=result,
            approver=approver if execute else None,
            plan_digest=run.plan.digest,
            recorded_at=clock(),
        )
        records.append(record)
        new_records.append(record)
        audit.append(
            actor,
            f"change.{status}",
            {
                "change_id": change_id,
                "action": action.action,
                "target": action.target,
                "result": result,
            },
        )
    write_json(run_dir / "changes.json", [record.model_dump(mode="json") for record in records])
    return new_records
