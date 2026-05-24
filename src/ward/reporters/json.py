"""Machine-readable JSON report."""

from __future__ import annotations

import json

from ..core.models import Finding, ScanReport


def _finding_dict(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "detector": finding.detector,
        "category": finding.category,
        "severity": finding.severity.value,
        "message": finding.message,
        "surface": finding.surface,
        "location": finding.location,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "references": list(finding.references),
    }


def render_json(report: ScanReport, *, indent: int = 2) -> str:
    payload = {
        "tool": {"name": "ward", "version": _ward_version()},
        "target": report.target,
        "threshold": report.threshold.value,
        "fail_on": report.fail_on.value,
        "verdict": report.verdict.value,
        "exit_code": report.exit_code,
        "summary": {
            "total": len(report.findings),
            "by_severity": _by_severity(report.findings),
            "by_category": _by_category(report.findings),
        },
        "findings": [_finding_dict(f) for f in report.findings],
    }
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def _by_severity(findings: tuple[Finding, ...]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity.value] = out.get(f.severity.value, 0) + 1
    return out


def _by_category(findings: tuple[Finding, ...]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.category] = out.get(f.category, 0) + 1
    return out


def _ward_version() -> str:
    from .. import __version__

    return __version__
