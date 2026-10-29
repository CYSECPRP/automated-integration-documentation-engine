from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from govflow.actions.base import SimulatedExecutor
from govflow.config import Config, Link
from govflow.docs_engine import build_site, markdown_escape, render_report_markdown, slugify
from govflow.policy_engine import CompiledPolicy
from govflow.workflow import Run, apply_run, approve_run, load_run
from tests.conftest import Clock


def _site(run: Run, policies: list[CompiledPolicy], config: Config, tmp_path: Path) -> Path:
    site = tmp_path / "site"
    build_site(load_run(run.path), policies, config, site)
    return site


def test_site_pages_and_reports(
    demo_run: Run, policies: list[CompiledPolicy], demo_config: Config, tmp_path: Path, clock: Clock
) -> None:
    approve_run(
        demo_run.path,
        approver="approver",
        digest=demo_run.plan.digest,
        config=demo_config,
        clock=clock,
    )
    apply_run(
        demo_run.path,
        config=demo_config,
        executor=SimulatedExecutor(),
        actor="approver",
        execute=True,
        clock=clock,
    )
    site = _site(demo_run, policies, demo_config, tmp_path)
    for name in (
        "index.html",
        "policies.html",
        "changes.html",
        "audit.html",
        "style.css",
        "report.md",
    ):
        assert (site / name).is_file()
    assert len(list((site / "resources").glob("*.html"))) == 12
    assert len(list((site / "runbooks").glob("*.html"))) == 17
    report = json.loads((site / "report.json").read_text(encoding="utf-8"))
    assert report["summary"]["findings"] == {"pass": 15, "fail": 22, "not_assessed": 6}
    assert report["audit"]["verified"] is True
    assert report["approval"]["approver"] == "approver"
    index = (site / "index.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in index
    assert "Approved by approver" in index
    changes = (site / "changes.html").read_text(encoding="utf-8")
    assert "simulated: would open a pull request" in changes
    markdown = (site / "report.md").read_text(encoding="utf-8")
    assert "| Failed | 22 |" in markdown
    assert "Approved by approver" in markdown


def test_links_stay_relative(
    demo_run: Run, policies: list[CompiledPolicy], demo_config: Config, tmp_path: Path
) -> None:
    site = _site(demo_run, policies, demo_config, tmp_path)
    for page in site.rglob("*.html"):
        for href in re.findall(r'href="([^"]+)"', page.read_text(encoding="utf-8")):
            assert href.startswith(("https://", "#")) or not re.match(r"^[a-z]+:|^/", href), (
                page,
                href,
            )
            if not href.startswith(("https://", "#")):
                assert (page.parent / href).resolve().exists(), (page, href)


def test_hostile_text_is_escaped(
    demo_run: Run, policies: list[CompiledPolicy], tmp_path: Path
) -> None:
    run = load_run(demo_run.path)
    resource = run.resources[0]
    run.resources[0] = resource.model_copy(update={"name": '<script>alert("x")</script>'})
    run.findings = [
        finding.model_copy(update={"resource_name": "evil | <img src=x onerror=alert(1)>"})
        if finding.resource_id == resource.id
        else finding
        for finding in run.findings
    ]
    config = Config(
        docs={"title": "<b>Title</b>", "links": [Link(label="Demo", href="demo/index.html")]}
    )
    site = tmp_path / "site"
    build_site(run, policies, config, site)
    pages = "".join(page.read_text(encoding="utf-8") for page in site.rglob("*.html"))
    assert "<script>" not in pages
    assert "<img src=x" not in pages
    assert "&lt;b&gt;Title&lt;/b&gt;" in pages
    assert 'href="demo/index.html"' in pages
    markdown = render_report_markdown(run)
    assert "evil \\| \\<img src=x onerror=alert(1)\\>" in markdown


def test_broken_audit_chain_is_shown(
    demo_run: Run, policies: list[CompiledPolicy], demo_config: Config, tmp_path: Path
) -> None:
    lines = demo_run.audit_path.read_text(encoding="utf-8").splitlines()
    demo_run.audit_path.write_text("\n".join([*lines[:-1], "garbage"]) + "\n", encoding="utf-8")
    site = tmp_path / "site"
    build_site(load_run(demo_run.path, verify_integrity=False), policies, demo_config, site)
    assert "Verification failed" in (site / "audit.html").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("value", "expected"),
    [("github:acme/app", "github-acme-app"), ("***", "item"), ("A B", "a-b")],
)
def test_slugify(value: str, expected: str) -> None:
    assert slugify(value) == expected


def test_markdown_escape() -> None:
    assert markdown_escape("a|b *c*\n<d>") == "a\\|b \\*c\\* \\<d\\>"


@pytest.mark.parametrize("href", ["javascript:alert(1)", "/absolute", "http://plain", "data:x"])
def test_unsafe_links_are_rejected(href: str) -> None:
    with pytest.raises(ValueError, match="https:// URLs or relative paths"):
        Link(label="x", href=href)
