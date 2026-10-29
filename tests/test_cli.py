from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from govflow.cli import app
from tests.conftest import demo_text

runner = CliRunner()


@pytest.fixture
def snapshot_config(tmp_path: Path) -> Path:
    (tmp_path / "aws.json").write_text(demo_text("aws_snapshot.json"), encoding="utf-8")
    config = tmp_path / "govflow.yaml"
    config.write_text(
        "version: 1\nname: cli test\ntargets:\n  snapshots: [aws.json]\n"
        "governance:\n  allowed_actions: [github.add_file]\n  allowed_targets: [github:acme/app]\n",
        encoding="utf-8",
    )
    return config


def _scan(config: Path, out: Path, *extra: str) -> tuple[int, Path]:
    result = runner.invoke(
        app, ["scan", "--config", str(config), "--out", str(out), "--actor", "ci", *extra]
    )
    runs = sorted(out.iterdir()) if out.exists() else []
    return result.exit_code, runs[-1] if runs else out


def test_version_and_help() -> None:
    assert runner.invoke(app, ["--version"]).stdout.startswith("govflow ")
    assert "scan" in runner.invoke(app, ["--help"]).stdout


def test_demo_builds_a_site(tmp_path: Path) -> None:
    result = runner.invoke(app, ["demo", "--out", str(tmp_path / "demo")])
    assert result.exit_code == 0, result.stdout
    assert "Approval gate held as expected" in result.stdout
    assert (tmp_path / "demo" / "site" / "index.html").is_file()


def test_scan_writes_outputs_and_applies_thresholds(
    snapshot_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(outputs))
    code, run_dir = _scan(snapshot_config, tmp_path / "runs")
    assert code == 0
    written = dict(line.split("=", 1) for line in outputs.read_text(encoding="utf-8").splitlines())
    assert written["executable_actions"] == "0"
    assert written["run_id"] == run_dir.name
    code, _ = _scan(snapshot_config, tmp_path / "runs", "--fail-on", "critical")
    assert code == 1


def test_scan_chains_and_rejects_tampered_history(snapshot_config: Path, tmp_path: Path) -> None:
    _, first = _scan(snapshot_config, tmp_path / "runs")
    code, second = _scan(
        snapshot_config, tmp_path / "more", "--chain-from", str(first / "audit.jsonl")
    )
    assert code == 0
    run = json.loads((second / "run.json").read_text(encoding="utf-8"))
    head = json.loads((first / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-1])["hash"]
    assert run["audit_genesis"] == head
    (first / "audit.jsonl").write_text("tampered\n", encoding="utf-8")
    code, _ = _scan(snapshot_config, tmp_path / "third", "--chain-from", str(first / "audit.jsonl"))
    assert code == 3


def test_canary_flow_end_to_end(
    snapshot_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GOVFLOW_GITHUB_TOKEN", raising=False)
    code, run_dir = _scan(snapshot_config, tmp_path / "runs", "--canary")
    assert code == 0
    plan = runner.invoke(app, ["plan", "show", str(run_dir)])
    assert "CANARY" in plan.stdout
    digest = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))["digest"]
    refused = runner.invoke(
        app, ["apply", str(run_dir), "--config", str(snapshot_config), "--simulate"]
    )
    assert refused.exit_code == 3
    assert "requires an approval" in refused.stderr
    wrong = runner.invoke(
        app,
        [
            "approve",
            str(run_dir),
            "--approver",
            "lead",
            "--digest",
            "x",
            "-c",
            str(snapshot_config),
        ],
    )
    assert wrong.exit_code == 3
    ok = runner.invoke(
        app,
        [
            "approve",
            str(run_dir),
            "--approver",
            "lead",
            "--digest",
            digest,
            "-c",
            str(snapshot_config),
        ],
    )
    assert ok.exit_code == 0, ok.stdout
    simulated = runner.invoke(
        app, ["apply", str(run_dir), "-c", str(snapshot_config), "--simulate"]
    )
    assert simulated.exit_code == 0
    assert "simulated" in simulated.stdout
    assert (
        runner.invoke(
            app, ["apply", str(run_dir), "-c", str(snapshot_config), "--execute"]
        ).exit_code
        == 2
    )
    both = runner.invoke(
        app, ["apply", str(run_dir), "-c", str(snapshot_config), "--execute", "--simulate"]
    )
    assert both.exit_code == 2


def test_docs_audit_and_policies_commands(
    snapshot_config: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, run_dir = _scan(snapshot_config, tmp_path / "runs")
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    docs = runner.invoke(
        app, ["docs", str(run_dir), "--site", str(tmp_path / "site"), "-c", str(snapshot_config)]
    )
    assert docs.exit_code == 0, docs.stdout
    assert "# cli test" in summary.read_text(encoding="utf-8")
    assert runner.invoke(app, ["audit", "verify", str(run_dir)]).exit_code == 0
    assert runner.invoke(app, ["audit", "verify", str(run_dir / "audit.jsonl")]).exit_code == 0
    listing = runner.invoke(app, ["policies", "list"])
    assert "GH-001" in listing.stdout
    (run_dir / "audit.jsonl").write_text("broken\n", encoding="utf-8")
    assert runner.invoke(app, ["audit", "verify", str(run_dir)]).exit_code == 3
    assert runner.invoke(app, ["plan", "show", str(run_dir)]).exit_code == 3


def test_configuration_errors_exit_2(tmp_path: Path) -> None:
    missing = runner.invoke(app, ["scan", "--config", str(tmp_path / "nope.yaml")])
    assert missing.exit_code == 2
    assert "cannot read" in missing.stderr
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 2\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", "--config", str(bad)]).exit_code == 2
    bad.write_text("targets:\n  github:\n    repositories: ['not a repo']\n", encoding="utf-8")
    assert runner.invoke(app, ["scan", "--config", str(bad)]).exit_code == 2
    bad.write_text("policies:\n  paths: [nowhere]\n", encoding="utf-8")
    assert runner.invoke(app, ["policies", "list", "-c", str(bad)]).exit_code == 2
    bad.write_text("targets:\n  snapshots: [nowhere.json]\n", encoding="utf-8")
    assert (
        runner.invoke(app, ["scan", "--config", str(bad), "--out", str(tmp_path / "r")]).exit_code
        == 2
    )


def test_collection_errors_exit_4(tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text("{nope", encoding="utf-8")
    config = tmp_path / "govflow.yaml"
    config.write_text("targets:\n  snapshots: [broken.json]\n", encoding="utf-8")
    code, _ = _scan(config, tmp_path / "runs")
    assert code == 4
