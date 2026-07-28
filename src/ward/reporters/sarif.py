"""SARIF 2.1.0 report for the GitHub Code Scanning tab.

The schema is the SARIF 2.1.0 spec as accepted by GitHub Advanced Security.
We produce a single ``runs[0]`` with ``tool.driver.rules`` populated from
the actual fired findings, and one ``results`` entry per finding.
"""

from __future__ import annotations

import json
from urllib.parse import quote

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


# Surfaces that genuinely correspond to a file on disk. Everything else -
# a branch name, a commit message, a PR body - is not a file, and describing
# it with a physicalLocation asks GitHub to annotate a path that does not
# exist. SARIF has logicalLocations for exactly this.
_FILE_SURFACES = frozenset({"file_name", "directory_name", "file_content", "code_comment"})


def _artifact_uri(location: str) -> str:
    """Turn a filesystem path into a valid SARIF artifact URI.

    The raw string used to go straight into ``artifactLocation.uri``, which
    fails official schema validation for perfectly ordinary paths. On Windows
    ``scan-local`` yields ``docs\\release notes.md``: backslashes are not path
    separators in a URI reference, and a literal space is not permitted at
    all. GitHub's code-scanning ingest is stricter than the CLI is, so the
    upload step failed on repos that were otherwise scanning fine.
    """
    return quote(location.replace("\\", "/"), safe="/")


def _location(finding: Finding, *, target: str) -> dict[str, object]:
    raw = finding.location or target or "untrusted-metadata"
    if finding.surface in _FILE_SURFACES:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": _artifact_uri(raw)},
                "region": {"startLine": 1},
            }
        }
    # A branch name or PR body has no file and no line. Claiming line 1 of a
    # file named "feat/ignore-previous-instructions" produced an annotation
    # pointing at a path that was never in the repository.
    return {
        "logicalLocations": [
            {
                "name": raw,
                "kind": "member",
                "fullyQualifiedName": f"{finding.surface}:{raw}",
            }
        ]
    }


def _result(finding: Finding, *, target: str) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {
            "text": (f"{finding.message}\nsurface: {finding.surface}\nevidence: {finding.evidence}")
        },
        "locations": [_location(finding, target=target)],
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
