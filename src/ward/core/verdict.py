"""Aggregate findings into a pass / warn / fail verdict."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Finding, ScanReport, Severity, Verdict

SCAN_INTEGRITY = "scan_integrity"


def aggregate(
    findings: Iterable[Finding],
    *,
    target: str,
    fail_on: Severity = Severity.HIGH,
    threshold: Severity = Severity.LOW,
) -> ScanReport:
    """Build a ``ScanReport`` from raw findings.

    ``threshold`` filters which findings are reported at all.
    ``fail_on`` is the lowest severity that escalates the run to FAIL.
    Anything between threshold and fail_on becomes a WARN.
    """
    # A scan-integrity finding is not a detection and must not be filterable.
    # It says "Ward did not look at this file", which is not a claim about
    # severity at all - and dropping it below the threshold turned "I could
    # not read three files" into a clean PASS, which is precisely the
    # partial-scan-reported-as-clean failure it exists to prevent.
    kept = tuple(
        f for f in findings if f.severity >= threshold or f.category == SCAN_INTEGRITY
    )
    if any(f.severity >= fail_on for f in kept):
        verdict = Verdict.FAIL
    elif kept:
        verdict = Verdict.WARN
    else:
        verdict = Verdict.PASS
    return ScanReport(
        findings=kept,
        verdict=verdict,
        fail_on=fail_on,
        threshold=threshold,
        target=target,
    )
