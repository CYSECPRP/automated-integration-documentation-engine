"""Executor interface plus a simulated executor for demos and rehearsals."""

from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
from string import Template
from typing import Protocol

from govflow.models import ChangeStatus, PlannedAction

FILE_TEMPLATES = frozenset({"security_md", "codeowners", "dependabot_github_actions", "canary"})


class ActionError(RuntimeError):
    """An action could not be carried out."""


@dataclass(frozen=True)
class ChangeContext:
    change_id: str
    run_id: str
    plan_digest: str
    approver: str | None


class Executor(Protocol):
    def describe(self, action: PlannedAction) -> str: ...

    def execute(
        self, action: PlannedAction, context: ChangeContext
    ) -> tuple[ChangeStatus, str]: ...


def describe_action(action: PlannedAction) -> str:
    if action.action == "github.add_file":
        repository = action.target.removeprefix("github:")
        return f"open a pull request on {repository} that adds {action.params.get('path', '?')}"
    return f"{action.action} on {action.target}"


def render_file(template: str, **values: str) -> str:
    if template not in FILE_TEMPLATES:
        raise ActionError(f"unknown file template {template!r}")
    text = (files("govflow") / "templates" / "remediation" / f"{template}.tmpl").read_text(
        encoding="utf-8"
    )
    return Template(text).safe_substitute(values)


class SimulatedExecutor:
    """Walks the full governed path without touching any external system."""

    def describe(self, action: PlannedAction) -> str:
        return describe_action(action)

    def execute(self, action: PlannedAction, context: ChangeContext) -> tuple[ChangeStatus, str]:
        return "simulated", f"simulated: would {describe_action(action)}"
