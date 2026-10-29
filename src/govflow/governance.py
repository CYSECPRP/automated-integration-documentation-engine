"""Governance: what may change, and only after an approval bound to the exact plan."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from govflow.config import Governance
from govflow.models import Approval, Finding, Plan, PlannedAction, Status
from govflow.policy_engine import CompiledPolicy

CANARY_POLICY = "CANARY"


class GovernanceError(RuntimeError):
    """An approval or execution request violates the governance rules."""


def classify(action: str, target: str, settings: Governance) -> tuple[bool, str | None]:
    if action not in settings.allowed_actions:
        return False, f"action '{action}' is not in governance.allowed_actions"
    if target not in settings.allowed_targets:
        return False, f"target '{target}' is not in governance.allowed_targets"
    return True, None


def build_plan(
    run_id: str,
    findings: Sequence[Finding],
    policies: Sequence[CompiledPolicy],
    settings: Governance,
    *,
    created_at: datetime,
) -> Plan:
    by_id = {compiled.id: compiled.policy for compiled in policies}
    actions: list[PlannedAction] = []
    for finding in findings:
        if finding.status is not Status.FAIL:
            continue
        policy = by_id[finding.policy_id]
        remediation = policy.remediation
        if remediation.action is None:
            continue
        allowed, reason = classify(remediation.action, finding.resource_id, settings)
        actions.append(
            PlannedAction(
                id=f"A{len(actions) + 1}",
                action=remediation.action,
                target=finding.resource_id,
                policy_id=policy.id,
                params=dict(remediation.params),
                summary=f"Remediate {policy.id} ({policy.title}) on {finding.resource_name}",
                allowed=allowed,
                blocked_reason=reason,
            )
        )
    return Plan(run_id=run_id, created_at=created_at, actions=actions)


def add_canary(plan: Plan, settings: Governance) -> Plan:
    """Add a harmless change whose only purpose is to exercise the approval gate."""
    target = next((item for item in settings.allowed_targets if item.startswith("github:")), None)
    if target is None or "github.add_file" not in settings.allowed_actions:
        raise GovernanceError(
            "a canary needs github.add_file and a GitHub target in the allowlists"
        )
    canary = PlannedAction(
        id=f"A{len(plan.actions) + 1}",
        action="github.add_file",
        target=target,
        policy_id=CANARY_POLICY,
        params={"path": f"docs/governance/canary/{plan.run_id}.md", "template": "canary"},
        summary="Canary change that proves the approval gate works end to end",
        allowed=True,
    )
    return plan.model_copy(update={"actions": [*plan.actions, canary]})


def approve(
    plan: Plan,
    *,
    approver: str,
    digest: str,
    settings: Governance,
    requester: str,
    approved_at: datetime,
    comment: str = "",
) -> Approval:
    if not approver.strip():
        raise GovernanceError("an approval must name the approver")
    if digest != plan.digest:
        raise GovernanceError(
            "digest does not match the plan; approve the exact plan that was reviewed"
        )
    if settings.separation_of_duties and approver == requester:
        raise GovernanceError("separation of duties: the approver must not be the requester")
    if not plan.executable:
        raise GovernanceError("the plan has no executable actions to approve")
    return Approval(
        run_id=plan.run_id,
        plan_digest=digest,
        approver=approver,
        approved_at=approved_at,
        comment=comment,
    )


def authorize_execution(plan: Plan, approval: Approval | None, settings: Governance) -> None:
    if approval is None:
        raise GovernanceError("execution requires an approval; run 'govflow approve' first")
    if approval.run_id != plan.run_id or approval.plan_digest != plan.digest:
        raise GovernanceError("the approval does not match this plan; it changed after approval")
    for action in plan.executable:
        allowed, reason = classify(action.action, action.target, settings)
        if not allowed:
            raise GovernanceError(f"{action.id}: {reason}")
