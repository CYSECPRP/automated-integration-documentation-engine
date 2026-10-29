"""Command-line interface for govflow."""

from __future__ import annotations

import getpass
import json
import os
from importlib.resources import files
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from govflow import __version__
from govflow.actions.base import Executor, SimulatedExecutor
from govflow.actions.github_pr import GitHubPullRequestExecutor
from govflow.audit import GENESIS, verify
from govflow.config import Config, ConfigError, load_config, parse_config_text
from govflow.connectors.base import CollectionError, Connector
from govflow.connectors.fixtures import fixture_transport
from govflow.connectors.github import GitHubClient, GitHubCollector
from govflow.connectors.snapshots import SnapshotConnector
from govflow.docs_engine import build_site, render_report_markdown
from govflow.expressions import PolicyError
from govflow.governance import GovernanceError
from govflow.models import Severity
from govflow.policy_engine import CompiledPolicy, exceeds_threshold, load_policies
from govflow.workflow import Run, RunError, apply_run, approve_run, load_run
from govflow.workflow import scan as run_scan

EXIT_FINDINGS = 1
EXIT_USAGE = 2
EXIT_GOVERNANCE = 3
EXIT_INTEGRATION = 4

app = typer.Typer(
    name="govflow",
    help=(
        "Automated Integration & Documentation Engine: "
        "governed IT automation with generated documentation."
    ),
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_enable=False,
)
plan_app = typer.Typer(help="Inspect remediation plans.", no_args_is_help=True)
audit_app = typer.Typer(help="Verify audit trails.", no_args_is_help=True)
policies_app = typer.Typer(help="Browse the policy catalog.", no_args_is_help=True)
app.add_typer(plan_app, name="plan")
app.add_typer(audit_app, name="audit")
app.add_typer(policies_app, name="policies")

console = Console(highlight=False)

ConfigOption = Annotated[Path, typer.Option("--config", "-c", help="Path to govflow.yaml.")]
OptionalConfig = Annotated[
    Path | None, typer.Option("--config", "-c", help="Optional govflow.yaml for titles and links.")
]
RunArgument = Annotated[Path, typer.Argument(help="Run directory created by 'govflow scan'.")]
ActorOption = Annotated[
    str | None, typer.Option(help="Who is acting (defaults to GITHUB_ACTOR or the OS user).")
]


def _fail(message: str, code: int) -> NoReturn:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code)


def _actor(explicit: str | None) -> str:
    if explicit:
        return explicit
    if os.environ.get("GITHUB_ACTOR"):
        return os.environ["GITHUB_ACTOR"]
    try:
        return getpass.getuser()
    except OSError:
        return "unknown"


def _token() -> str | None:
    return os.environ.get("GOVFLOW_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN") or None


def _config(path: Path | None) -> Config:
    if path is None:
        return Config()
    try:
        return load_config(path)
    except ConfigError as exc:
        _fail(str(exc), EXIT_USAGE)


def _policies(config: Config) -> list[CompiledPolicy]:
    try:
        return load_policies(config.policies.paths, include_builtin=config.policies.include_builtin)
    except PolicyError as exc:
        _fail(str(exc), EXIT_USAGE)


def _run(path: Path, *, verify_integrity: bool = True) -> Run:
    try:
        return load_run(path, verify_integrity=verify_integrity)
    except RunError as exc:
        _fail(str(exc), EXIT_GOVERNANCE)


def _genesis(chain_from: Path | None) -> str:
    if chain_from is None:
        return GENESIS
    result = verify(chain_from, genesis=None)
    if not result.ok:
        _fail(
            f"previous audit log {chain_from} failed verification: {result.error}", EXIT_GOVERNANCE
        )
    return result.head


def _connectors(config: Config, client: GitHubClient) -> list[Connector]:
    connectors: list[Connector] = []
    if config.targets.github.repositories:
        connectors.append(GitHubCollector(client, config.targets.github.repositories))
    for path in config.targets.snapshots:
        try:
            connectors.append(SnapshotConnector.from_path(path))
        except CollectionError as exc:
            _fail(str(exc), EXIT_USAGE)
    return connectors


def _write_outputs(values: dict[str, str]) -> None:
    """Expose results to later GitHub Actions steps."""
    target = os.environ.get("GITHUB_OUTPUT")
    if not target:
        return
    with Path(target).open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def _print_summary(run: Run) -> None:
    counts = run.info.counts
    table = Table(title=f"govflow run {run.info.run_id}")
    for column in ("Resources", "Pass", "Fail", "Not assessed", "Planned", "Executable"):
        table.add_column(column, justify="right")
    table.add_row(
        str(run.info.resource_count),
        str(counts.get("pass", 0)),
        str(counts.get("fail", 0)),
        str(counts.get("not_assessed", 0)),
        str(len(run.plan.actions)),
        str(len(run.plan.executable)),
    )
    console.print(table)
    console.print(f"Run directory: {run.path}", markup=False)
    console.print(f"Plan digest:   {run.plan.digest}", markup=False)
    for error in run.info.collection_errors:
        console.print(f"collection error: {error}", markup=False, style="red")


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"govflow {__version__}")
        raise typer.Exit


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_show_version, is_eager=True, help="Show the version."),
    ] = False,
) -> None:
    """Automated Integration & Documentation Engine."""


@app.command()
def demo(
    out: Annotated[Path, typer.Option(help="Folder for the demo run and site.")] = Path(
        "govflow-demo"
    ),
) -> None:
    """Run the whole governed pipeline offline against bundled fixtures."""
    data = files("govflow") / "demo_data"
    config = parse_config_text(
        (data / "govflow.demo.yaml").read_text(encoding="utf-8"), "demo config"
    )
    routes = json.loads((data / "github_api.json").read_text(encoding="utf-8"))
    policies = load_policies()
    with GitHubClient(transport=fixture_transport(routes)) as client:
        connectors: list[Connector] = [
            GitHubCollector(client, config.targets.github.repositories),
            SnapshotConnector(
                (data / "aws_snapshot.json").read_text(encoding="utf-8"), "aws_snapshot.json"
            ),
            SnapshotConnector(
                (data / "gcp_snapshot.json").read_text(encoding="utf-8"), "gcp_snapshot.json"
            ),
        ]
        run = run_scan(config, connectors, policies, out / "runs", actor="demo-requester")
    executor = SimulatedExecutor()
    try:
        apply_run(run.path, config=config, executor=executor, actor="demo-requester", execute=True)
    except GovernanceError as exc:
        console.print(f"Approval gate held as expected: {exc}", markup=False)
    approve_run(
        run.path,
        approver="demo-approver",
        digest=run.plan.digest,
        config=config,
        comment="Reviewed the allowlisted pull requests for acme-demo/payments-api.",
    )
    apply_run(run.path, config=config, executor=executor, actor="demo-approver", execute=True)
    final = load_run(run.path)
    index = build_site(final, policies, config, out / "site")
    _print_summary(final)
    console.print(
        f"Open {index} in a browser to explore the generated documentation.", markup=False
    )


@app.command()
def scan(
    config: ConfigOption = Path("govflow.yaml"),
    out: Annotated[Path, typer.Option(help="Directory that receives the run folder.")] = Path(
        "runs"
    ),
    chain_from: Annotated[
        Path | None, typer.Option(help="audit.jsonl of the previous run to chain this run to.")
    ] = None,
    fail_on: Annotated[
        Severity | None, typer.Option(help="Exit 1 if a failure at or above this severity exists.")
    ] = None,
    canary: Annotated[
        bool, typer.Option(help="Add a canary change that exercises the approval gate.")
    ] = False,
    actor: ActorOption = None,
) -> None:
    """Collect from every target, evaluate the policies and write an audited, planned run."""
    cfg = _config(config)
    policies = _policies(cfg)
    genesis = _genesis(chain_from)
    with GitHubClient(_token(), base_url=cfg.targets.github.api_url) as client:
        connectors = _connectors(cfg, client)
        try:
            run = run_scan(
                cfg,
                connectors,
                policies,
                out,
                actor=_actor(actor),
                genesis=genesis,
                canary=canary,
            )
        except GovernanceError as exc:
            _fail(str(exc), EXIT_GOVERNANCE)
    _print_summary(run)
    _write_outputs(
        {
            "run_id": run.info.run_id,
            "run_dir": run.path.as_posix(),
            "plan_digest": run.plan.digest,
            "executable_actions": str(len(run.plan.executable)),
        }
    )
    if run.info.collection_errors:
        raise typer.Exit(EXIT_INTEGRATION)
    threshold = fail_on or cfg.governance.fail_on
    if threshold is not None and exceeds_threshold(run.findings, threshold):
        console.print(f"Failed checks at or above '{threshold.value}' severity.", markup=False)
        raise typer.Exit(EXIT_FINDINGS)


@plan_app.command("show")
def plan_show(run_dir: RunArgument) -> None:
    """Show planned actions and the digest an approver must sign."""
    run = _run(run_dir)
    table = Table("ID", "Action", "Target", "Policy", "Governance")
    for action in run.plan.actions:
        verdict = "allowed" if action.allowed else f"blocked: {action.blocked_reason}"
        table.add_row(
            Text(action.id),
            Text(f"{action.action} {action.params.get('path', '')}".strip()),
            Text(action.target),
            Text(action.policy_id),
            Text(verdict),
        )
    console.print(table)
    console.print(f"Plan digest: {run.plan.digest}", markup=False)


@app.command()
def approve(
    run_dir: RunArgument,
    approver: Annotated[str, typer.Option(help="Name of the person approving.")],
    digest: Annotated[str, typer.Option(help="The plan digest that was reviewed.")],
    config: ConfigOption = Path("govflow.yaml"),
    comment: Annotated[str, typer.Option(help="Reason recorded with the approval.")] = "",
) -> None:
    """Record an approval bound to the exact plan digest."""
    cfg = _config(config)
    try:
        approval = approve_run(
            run_dir, approver=approver, digest=digest, config=cfg, comment=comment
        )
    except (GovernanceError, RunError) as exc:
        _fail(str(exc), EXIT_GOVERNANCE)
    console.print(f"Plan {approval.plan_digest} approved by {approval.approver}.", markup=False)


@app.command()
def apply(
    run_dir: RunArgument,
    config: ConfigOption = Path("govflow.yaml"),
    execute: Annotated[
        bool, typer.Option("--execute", help="Make real changes (needs an approval and a token).")
    ] = False,
    simulate: Annotated[
        bool, typer.Option("--simulate", help="Enforce the approval gate but only simulate.")
    ] = False,
    actor: ActorOption = None,
) -> None:
    """Dry-run by default; --execute applies approved, allowlisted actions via pull requests."""
    cfg = _config(config)
    if execute and simulate:
        _fail("choose either --execute or --simulate", EXIT_USAGE)
    token = _token()
    if execute and not token:
        _fail("--execute needs GOVFLOW_GITHUB_TOKEN or GITHUB_TOKEN", EXIT_USAGE)
    with GitHubClient(token, base_url=cfg.targets.github.api_url) as client:
        executor: Executor = GitHubPullRequestExecutor(client) if execute else SimulatedExecutor()
        try:
            records = apply_run(
                run_dir,
                config=cfg,
                executor=executor,
                actor=_actor(actor),
                execute=execute or simulate,
            )
        except (GovernanceError, RunError) as exc:
            _fail(str(exc), EXIT_GOVERNANCE)
    table = Table("Change", "Status", "Result")
    for record in records:
        table.add_row(Text(record.id), Text(record.status), Text(record.result))
    console.print(table)
    if any(record.status == "failed" for record in records):
        raise typer.Exit(EXIT_INTEGRATION)


@app.command()
def docs(
    run_dir: RunArgument,
    site: Annotated[Path, typer.Option(help="Output directory for the static site.")] = Path(
        "site"
    ),
    config: OptionalConfig = None,
) -> None:
    """Render the evidence site, report.md and report.json for a run."""
    cfg = _config(config)
    policies = _policies(cfg)
    run = _run(run_dir, verify_integrity=False)
    index = build_site(run, policies, cfg, site)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as handle:
            handle.write(render_report_markdown(run) + "\n")
    console.print(f"Site written to {index}", markup=False)


@audit_app.command("verify")
def audit_verify(
    path: Annotated[Path, typer.Argument(help="A run directory or an audit.jsonl file.")],
    genesis: Annotated[
        str | None, typer.Option(help="Expected first prev_hash (defaults to the run's).")
    ] = None,
) -> None:
    """Verify the hash chain of an audit log."""
    expected: str | None = genesis
    log = path
    if path.is_dir():
        run = _run(path, verify_integrity=False)
        log, expected = path / "audit.jsonl", genesis or run.info.audit_genesis
    result = verify(log, genesis=expected)
    if not result.ok:
        _fail(f"audit chain broken: {result.error}", EXIT_GOVERNANCE)
    console.print(f"Audit chain verified: {result.count} events, head {result.head}", markup=False)


@policies_app.command("list")
def policies_list(config: OptionalConfig = None) -> None:
    """List the policies that would be evaluated."""
    table = Table("ID", "Severity", "Resource", "Title")
    for compiled in _policies(_config(config)):
        policy = compiled.policy
        table.add_row(
            Text(policy.id), Text(policy.severity.value), Text(policy.resource), Text(policy.title)
        )
    console.print(table)


def main() -> None:
    app()
