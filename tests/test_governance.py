from __future__ import annotations

import json

import pytest

from govflow.actions.base import SimulatedExecutor
from govflow.audit import read_events, verify
from govflow.config import Config, Governance
from govflow.governance import GovernanceError, add_canary, approve, authorize_execution
from govflow.models import Plan, PlannedAction
from govflow.workflow import Run, RunError, apply_run, approve_run, load_run
from tests.conftest import RUN_ID, Clock


def _events(run: Run) -> list[str]:
    return [event.event for event in read_events(run.audit_path)]


def test_plan_respects_allowlists(demo_run: Run) -> None:
    allowed = [action for action in demo_run.plan.actions if action.allowed]
    blocked = [action for action in demo_run.plan.actions if not action.allowed]
    assert {action.target for action in allowed} == {"github:acme-demo/payments-api"}
    assert {action.policy_id for action in allowed} == {"GH-002", "GH-003", "GH-004"}
    assert {action.target for action in blocked} == {"github:acme-demo/legacy-tools"}
    assert all("allowed_targets" in (action.blocked_reason or "") for action in blocked)


def test_execution_without_approval_is_refused_and_audited(
    demo_run: Run, demo_config: Config, clock: Clock
) -> None:
    with pytest.raises(GovernanceError, match="requires an approval"):
        apply_run(
            demo_run.path,
            config=demo_config,
            executor=SimulatedExecutor(),
            actor="requester",
            execute=True,
            clock=clock,
        )
    assert _events(demo_run)[-1] == "apply.refused"
    assert verify(demo_run.audit_path).ok


def test_approval_must_match_digest_and_separate_duties(
    demo_run: Run, demo_config: Config, clock: Clock
) -> None:
    with pytest.raises(GovernanceError, match="digest does not match"):
        approve_run(
            demo_run.path, approver="approver", digest="0" * 64, config=demo_config, clock=clock
        )
    with pytest.raises(GovernanceError, match="separation of duties"):
        approve_run(
            demo_run.path,
            approver="requester",
            digest=demo_run.plan.digest,
            config=demo_config,
            clock=clock,
        )
    assert _events(demo_run)[-2:] == ["approval.rejected", "approval.rejected"]


def test_dry_run_then_approved_simulated_execution(
    demo_run: Run, demo_config: Config, clock: Clock
) -> None:
    dry = apply_run(
        demo_run.path,
        config=demo_config,
        executor=SimulatedExecutor(),
        actor="requester",
        execute=False,
        clock=clock,
    )
    assert [record.status for record in dry].count("dry-run") == 3
    assert [record.status for record in dry].count("skipped") == 3

    approval = approve_run(
        demo_run.path,
        approver="approver",
        digest=demo_run.plan.digest,
        config=demo_config,
        comment="ok",
        clock=clock,
    )
    assert approval.plan_digest == demo_run.plan.digest

    applied = apply_run(
        demo_run.path,
        config=demo_config,
        executor=SimulatedExecutor(),
        actor="approver",
        execute=True,
        clock=clock,
    )
    assert [record.status for record in applied].count("simulated") == 3
    assert all(record.approver == "approver" for record in applied)
    assert applied[0].id == f"CR-{RUN_ID}-A1-2"

    again = apply_run(
        demo_run.path,
        config=demo_config,
        executor=SimulatedExecutor(),
        actor="approver",
        execute=True,
        clock=clock,
    )
    assert {record.result for record in again if record.action.allowed} == {
        "already executed by an earlier apply"
    }
    reloaded = load_run(demo_run.path)
    assert len(reloaded.changes) == 18
    assert reloaded.approval is not None
    assert verify(demo_run.audit_path).ok


def test_tampered_plan_is_rejected(demo_run: Run) -> None:
    plan_path = demo_run.path / "plan.json"
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    data["actions"][3]["allowed"] = True
    plan_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(RunError, match="does not match the plan digest"):
        load_run(demo_run.path)


def test_tampered_audit_log_is_rejected(demo_run: Run) -> None:
    lines = demo_run.audit_path.read_text(encoding="utf-8").splitlines()
    demo_run.audit_path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    with pytest.raises(RunError, match="audit log failed verification"):
        load_run(demo_run.path)


def test_missing_or_corrupt_run_directory(demo_run: Run) -> None:
    with pytest.raises(RunError, match="not a govflow run directory"):
        load_run(demo_run.path / "nope")
    (demo_run.path / "findings.json").write_text("{broken", encoding="utf-8")
    with pytest.raises(RunError, match="unreadable"):
        load_run(demo_run.path)


def _plan(*actions: PlannedAction) -> Plan:
    return Plan(run_id="r", created_at="2026-10-29T09:00:00Z", actions=list(actions))


def _action(target: str = "github:o/r", allowed: bool = True) -> PlannedAction:
    return PlannedAction(
        id="A1",
        action="github.add_file",
        target=target,
        policy_id="GH-002",
        params={"path": "SECURITY.md", "template": "security_md"},
        summary="s",
        allowed=allowed,
    )


def test_governance_rules_in_isolation() -> None:
    settings = Governance(allowed_actions=["github.add_file"], allowed_targets=["github:o/r"])
    plan = _plan(_action())
    when = plan.created_at
    with pytest.raises(GovernanceError, match="name the approver"):
        approve(
            plan,
            approver=" ",
            digest=plan.digest,
            settings=settings,
            requester="x",
            approved_at=when,
        )
    empty = _plan(_action(allowed=False))
    with pytest.raises(GovernanceError, match="no executable actions"):
        approve(
            empty,
            approver="a",
            digest=empty.digest,
            settings=settings,
            requester="x",
            approved_at=when,
        )
    approval = approve(
        plan, approver="a", digest=plan.digest, settings=settings, requester="x", approved_at=when
    )
    authorize_execution(plan, approval, settings)
    changed = _plan(_action(target="github:o/other"))
    with pytest.raises(GovernanceError, match="changed after approval"):
        authorize_execution(changed, approval, settings)
    narrowed = Governance(allowed_actions=["github.add_file"], allowed_targets=[])
    with pytest.raises(GovernanceError, match="allowed_targets"):
        authorize_execution(plan, approval, narrowed)
    no_actions = Governance(allowed_actions=[], allowed_targets=["github:o/r"])
    with pytest.raises(GovernanceError, match="allowed_actions"):
        authorize_execution(plan, approval, no_actions)


def test_canary_needs_allowlisted_github_target() -> None:
    plan = _plan()
    canary = add_canary(
        plan,
        Governance(allowed_actions=["github.add_file"], allowed_targets=["aws:x", "github:o/r"]),
    )
    action = canary.actions[-1]
    assert action.target == "github:o/r"
    assert action.params["path"] == "docs/governance/canary/r.md"
    with pytest.raises(GovernanceError, match="canary"):
        add_canary(plan, Governance(allowed_actions=["github.add_file"], allowed_targets=["aws:x"]))
