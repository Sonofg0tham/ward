"""Tests for verdict aggregation."""

from __future__ import annotations

from ward.core.models import Finding, Severity, Verdict
from ward.core.verdict import aggregate


def _make_finding(severity: Severity, rule_id: str = "io.test") -> Finding:
    return Finding(
        rule_id=rule_id,
        detector="instruction_override",
        category="instruction_override",
        severity=severity,
        message="test",
        surface="pr_body",
        location="t",
        evidence="x",
    )


def test_empty_findings_is_pass():
    report = aggregate([], target="t")
    assert report.verdict is Verdict.PASS
    assert report.exit_code == 0


def test_high_finding_with_default_fail_on_is_fail():
    report = aggregate([_make_finding(Severity.HIGH)], target="t")
    assert report.verdict is Verdict.FAIL
    assert report.exit_code == 2


def test_medium_finding_is_warn_by_default():
    report = aggregate([_make_finding(Severity.MEDIUM)], target="t")
    assert report.verdict is Verdict.WARN
    assert report.exit_code == 1


def test_threshold_filters_low_findings():
    findings = [_make_finding(Severity.LOW), _make_finding(Severity.HIGH, "io.h")]
    report = aggregate(findings, target="t", threshold=Severity.MEDIUM)
    assert len(report.findings) == 1
    assert report.findings[0].rule_id == "io.h"


def test_fail_on_medium_escalates_to_fail():
    report = aggregate([_make_finding(Severity.MEDIUM)], target="t", fail_on=Severity.MEDIUM)
    assert report.verdict is Verdict.FAIL
