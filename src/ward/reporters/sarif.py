"""SARIF 2.1.0 report for the GitHub Code Scanning tab.

The schema is the SARIF 2.1.0 spec as accepted by GitHub Advanced Security.
We produce a single ``runs[0]`` with ``tool.driver.rules`` populated from
the actual fired findings, and one ``results`` entry per finding.
"""

from __future__ import annotations

import json

from ..core.models import Finding, ScanReport, Severity

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

_SEVERITY_SCORE = {
    Severity.INFO: "2.0",
    Severity.LOW: "3.5",
    Severity.MEDIUM: "5.5",
    Severity.HIGH: "8.0",
    Severity.CRITICAL: "9.5",
}


def _rule_descriptor(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.replace(".", "_"),
        "shortDescription": {"text": finding.message[:120]},
        "fullDescription": {"text": finding.message},
        "helpUri": finding.references[0]
        if finding.references
        else "https://github.com/sonofg0tham/ward",
        "help": {
            "text": finding.remediation or "Reject the metadata and review the source.",
        },
        "properties": {
            "category": finding.category,
            "tags": ["security", "prompt-injection", finding.category],
            "security-severity": _SEVERITY_SCORE[finding.severity],
        },
        "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
    }


def _result(finding: Finding, *, target: str) -> dict[str, object]:
    location_uri = finding.location or target or "untrusted-metadata"
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {
            "text": (f"{finding.message}\nsurface: {finding.surface}\nevidence: {finding.evidence}")
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": location_uri},
                    "region": {"startLine": 1},
                }
            }
        ],
        "properties": {
            "surface": finding.surface,
            "category": finding.category,
        },
    }


def render_sarif(report: ScanReport) -> str:
    """Produce a valid SARIF 2.1.0 document as a JSON string."""
    seen: dict[str, dict[str, object]] = {}
    for finding in report.findings:
        seen.setdefault(finding.rule_id, _rule_descriptor(finding))

    rules = list(seen.values())
    results = [_result(f, target=report.target) for f in report.findings]

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ward",
                        "version": _ward_version(),
                        "informationUri": "https://github.com/sonofg0tham/ward",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target": report.target,
                    "verdict": report.verdict.value,
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _ward_version() -> str:
    from .. import __version__

    return __version__
