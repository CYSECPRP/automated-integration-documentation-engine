from __future__ import annotations

from pathlib import Path

import pytest

from govflow.actions.base import FILE_TEMPLATES
from govflow.expressions import PolicyError
from govflow.models import Severity, Status
from govflow.policy_engine import (
    CompiledPolicy,
    compile_policy,
    compliance_score,
    exceeds_threshold,
    load_policies,
)
from govflow.workflow import Run

VALID = """
id: TST-001
title: Example policy for tests
resource: aws.s3.bucket
severity: low
rationale: Testing.
check: {path: versioning.Status, op: eq, value: Enabled}
remediation:
  steps: [Do the thing.]
"""

EXPECTED = {
    ("GH-001", "github:acme-demo/payments-api"): Status.FAIL,
    ("GH-001", "github:acme-demo/docs-site"): Status.PASS,
    ("GH-006", "github:acme-demo/payments-api"): Status.FAIL,
    ("GH-006", "github:acme-demo/legacy-tools"): Status.PASS,
    ("GH-007", "github:acme-demo/payments-api"): Status.FAIL,
    ("GH-008", "github:acme-demo/payments-api"): Status.FAIL,
    ("GH-008", "github:acme-demo/docs-site"): Status.NOT_ASSESSED,
    ("GH-009", "github:acme-demo/payments-api"): Status.FAIL,
    ("GH-010", "github:acme-demo/payments-api"): Status.FAIL,
    ("GH-010", "github:acme-demo/legacy-tools"): Status.NOT_ASSESSED,
    ("AWS-001", "aws:111122223333:acme-public-assets"): Status.FAIL,
    ("AWS-001", "aws:111122223333:acme-audit-logs"): Status.PASS,
    ("AWS-003", "aws:111122223333:sg-0a1b2c3d4e5f60001"): Status.FAIL,
    ("AWS-003", "aws:111122223333:sg-0a1b2c3d4e5f60002"): Status.PASS,
    ("AWS-004", "aws:111122223333:account-summary"): Status.FAIL,
    ("GCP-001", "gcp:acme-demo-prod:acme-demo-exports"): Status.FAIL,
    ("GCP-002", "gcp:acme-demo-prod:acme-demo-backups"): Status.PASS,
    ("GCP-003", "gcp:acme-demo-prod:allow-ssh-anywhere"): Status.FAIL,
    ("GCP-003", "gcp:acme-demo-prod:allow-internal"): Status.PASS,
}


def test_builtin_catalog_is_valid(policies: list[CompiledPolicy]) -> None:
    ids = [compiled.id for compiled in policies]
    assert len(ids) == 17
    assert len(set(ids)) == len(ids)
    for compiled in policies:
        remediation = compiled.policy.remediation
        if remediation.action == "github.add_file":
            assert remediation.params["template"] in FILE_TEMPLATES
            assert remediation.params["path"]


def test_demo_findings_match_expectations(demo_run: Run) -> None:
    statuses = {(f.policy_id, f.resource_id): f.status for f in demo_run.findings}
    for key, expected in EXPECTED.items():
        assert statuses[key] is expected, key
    assert demo_run.info.counts == {"pass": 15, "fail": 22, "not_assessed": 6}


def test_not_assessed_findings_explain_why(demo_run: Run) -> None:
    finding = next(
        f
        for f in demo_run.findings
        if f.policy_id == "GH-008" and f.resource_id == "github:acme-demo/docs-site"
    )
    assert "needs admin access" in finding.detail
    assert str(finding.evidence["security_and_analysis.secret_scanning"]).startswith("unavailable")


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("id: [unclosed", "invalid YAML"),
        ("- just a list", "mapping at the top level"),
        (VALID.replace("TST-001", "bad"), "id"),
        (VALID.replace("aws.s3.bucket", "azure.vm"), "unknown resource type"),
        (VALID.replace("op: eq", "op: like"), "unknown operator"),
    ],
)
def test_compile_policy_rejects_bad_files(text: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        compile_policy(text, "test.yaml")


def test_extra_policy_directories(tmp_path: Path) -> None:
    (tmp_path / "custom.yaml").write_text(VALID, encoding="utf-8")
    loaded = load_policies([tmp_path], include_builtin=False)
    assert [compiled.id for compiled in loaded] == ["TST-001"]
    (tmp_path / "duplicate.yaml").write_text(VALID, encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate policy id"):
        load_policies([tmp_path], include_builtin=False)
    with pytest.raises(PolicyError, match="does not exist"):
        load_policies([tmp_path / "missing"], include_builtin=False)


def test_scores_and_thresholds(demo_run: Run) -> None:
    assert compliance_score(demo_run.findings) == pytest.approx(40.5)
    assert compliance_score([]) is None
    assert exceeds_threshold(demo_run.findings, Severity.CRITICAL)
    assert not exceeds_threshold(
        [f for f in demo_run.findings if f.status is Status.PASS], Severity.LOW
    )
