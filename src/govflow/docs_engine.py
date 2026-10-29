"""Documentation engine: a static evidence site plus Markdown and JSON reports."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from govflow import __version__
from govflow.actions.base import ChangeContext
from govflow.audit import AuditEvent, Verification, read_events, verify
from govflow.config import Config
from govflow.models import Finding, PlannedAction, Resource, Severity, Status
from govflow.policy_engine import (
    CompiledPolicy,
    compliance_score,
    failed_by_severity,
    summarize,
)
from govflow.util import write_json
from govflow.workflow import Run

_STATUS_ORDER = {Status.FAIL: 0, Status.NOT_ASSESSED: 1, Status.PASS: 2}
_MARKDOWN_SPECIAL = re.compile(r"([\\`*_|\[\]<>#])")


def slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "item"


def markdown_escape(value: Any) -> str:
    return _MARKDOWN_SPECIAL.sub(r"\\\1", " ".join(str(value).split()))


def _timestamp(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if value else "-"


def _short(value: str | None) -> str:
    return (value or "")[:12]


def _environment(*, html: bool) -> Environment:
    loader = PackageLoader("govflow", "templates")
    if html:
        env = Environment(
            loader=loader,
            autoescape=True,
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )
    else:
        # Markdown output: values are escaped explicitly with the "md" filter.
        env = Environment(
            loader=loader,
            autoescape=False,  # noqa: S701
            undefined=StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
    env.filters.update(md=markdown_escape, ts=_timestamp, short=_short, slug=slugify)
    return env


@dataclass(frozen=True)
class ResourceView:
    resource: Resource
    slug: str
    findings: list[Finding]
    counts: dict[str, int]
    score: float | None


def _finding_order(finding: Finding) -> tuple[int, int, str, str]:
    return (
        _STATUS_ORDER[finding.status],
        -finding.severity.rank,
        finding.policy_id,
        finding.resource_name,
    )


def _resource_views(run: Run) -> list[ResourceView]:
    grouped: dict[str, list[Finding]] = {}
    for finding in run.findings:
        grouped.setdefault(finding.resource_id, []).append(finding)
    views: list[ResourceView] = []
    used: set[str] = set()
    for resource in sorted(run.resources, key=lambda item: (item.provider, item.name)):
        slug = base = slugify(resource.id)
        counter = 2
        while slug in used:
            slug, counter = f"{base}-{counter}", counter + 1
        used.add(slug)
        findings = sorted(grouped.get(resource.id, []), key=_finding_order)
        views.append(
            ResourceView(resource, slug, findings, summarize(findings), compliance_score(findings))
        )
    return views


def build_report(run: Run, verification: Verification) -> dict[str, Any]:
    findings = sorted(run.findings, key=lambda item: (item.resource_id, item.policy_id))
    return {
        "engine": {"name": "govflow", "version": __version__},
        "run": run.info.model_dump(mode="json"),
        "summary": {
            "resources": len(run.resources),
            "policies": run.info.policy_count,
            "findings": summarize(run.findings),
            "failed_by_severity": failed_by_severity(run.findings),
            "compliance_score": compliance_score(run.findings),
        },
        "audit": {
            "verified": verification.ok,
            "events": verification.count,
            "genesis": verification.genesis,
            "head": verification.head,
            "error": verification.error,
        },
        "plan": {
            "digest": run.plan.digest,
            "actions": [action.model_dump(mode="json") for action in run.plan.actions],
        },
        "approval": run.approval.model_dump(mode="json") if run.approval else None,
        "changes": [change.model_dump(mode="json") for change in run.changes],
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }


def _severity_rows(run: Run) -> list[tuple[str, int]]:
    counts = failed_by_severity(run.findings)
    order = sorted(Severity, key=lambda severity: -severity.rank)
    return [(severity.value, counts[severity.value]) for severity in order]


def _events(run: Run) -> list[AuditEvent]:
    try:
        return read_events(run.audit_path)
    except (OSError, ValueError):
        return []


def _render(env: Environment, template: str, target: Path, **context: Any) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(env.get_template(template).render(**context), encoding="utf-8", newline="\n")


def build_site(
    run: Run, policies: Sequence[CompiledPolicy], config: Config, site_dir: Path
) -> Path:
    verification = verify(run.audit_path, genesis=run.info.audit_genesis)
    report = build_report(run, verification)
    views = _resource_views(run)
    failing = sorted(
        (finding for finding in run.findings if finding.status is Status.FAIL), key=_finding_order
    )
    env = _environment(html=True)
    common: dict[str, Any] = {
        "site_title": config.docs.title,
        "links": config.docs.links,
        "version": __version__,
        "info": run.info,
        "report": report,
        "verification": verification,
        "slugs": {view.resource.id: view.slug for view in views},
        "policy_ids": {compiled.id for compiled in policies},
    }
    _render(
        env,
        "site/index.html.j2",
        site_dir / "index.html",
        root="",
        active="overview",
        page_title="Overview",
        views=views,
        failing=failing,
        severity_rows=_severity_rows(run),
        plan=run.plan,
        approval=run.approval,
        **common,
    )
    for view in views:
        _render(
            env,
            "site/resource.html.j2",
            site_dir / "resources" / f"{view.slug}.html",
            root="../",
            active="overview",
            page_title=view.resource.name,
            view=view,
            **common,
        )
    _render(
        env,
        "site/policies.html.j2",
        site_dir / "policies.html",
        root="",
        active="policies",
        page_title="Policies",
        policies=policies,
        **common,
    )
    for compiled in policies:
        affected = [finding for finding in failing if finding.policy_id == compiled.id]
        _render(
            env,
            "site/runbook.html.j2",
            site_dir / "runbooks" / f"{compiled.id.lower()}.html",
            root="../",
            active="policies",
            page_title=f"Runbook {compiled.id}",
            compiled=compiled,
            affected=affected,
            **common,
        )
    _render(
        env,
        "site/changes.html.j2",
        site_dir / "changes.html",
        root="",
        active="changes",
        page_title="Changes",
        plan=run.plan,
        approval=run.approval,
        changes=run.changes,
        **common,
    )
    _render(
        env,
        "site/audit.html.j2",
        site_dir / "audit.html",
        root="",
        active="audit",
        page_title="Audit log",
        events=_events(run),
        **common,
    )
    stylesheet = (files("govflow") / "static" / "style.css").read_text(encoding="utf-8")
    (site_dir / "style.css").write_text(stylesheet, encoding="utf-8", newline="\n")
    write_json(site_dir / "report.json", report)
    (site_dir / "report.md").write_text(
        render_report_markdown(run, verification), encoding="utf-8", newline="\n"
    )
    return site_dir / "index.html"


def render_report_markdown(run: Run, verification: Verification | None = None) -> str:
    verification = verification or verify(run.audit_path, genesis=run.info.audit_genesis)
    env = _environment(html=False)
    findings = sorted(run.findings, key=_finding_order)
    return env.get_template("report.md.j2").render(
        version=__version__,
        info=run.info,
        summary=build_report(run, verification)["summary"],
        verification=verification,
        failing=[finding for finding in findings if finding.status is Status.FAIL],
        not_assessed=[finding for finding in findings if finding.status is Status.NOT_ASSESSED],
        plan=run.plan,
        approval=run.approval,
        changes=run.changes,
    )


def change_record_markdown(
    action: PlannedAction, context: ChangeContext, *, description: str
) -> str:
    env = _environment(html=False)
    return env.get_template("change_record.md.j2").render(
        version=__version__, action=action, context=context, description=description
    )
