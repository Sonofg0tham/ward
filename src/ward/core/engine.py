"""Top-level scan engine. Builds inputs, runs all detectors, aggregates."""

from __future__ import annotations

from collections.abc import Iterable

from fnmatch import fnmatchcase

from ..detectors import ALL_DETECTOR_CLASSES
from .models import Finding, ScanInput, ScanReport, Severity, Surface
from .normalise import (
    decode_candidates,
    evasion_forms,
    extract_suppressions,
    normalise_text,
    split_identifier,
)
from .rules import RulePack
from .verdict import aggregate

# Surfaces whose text uses hyphens / underscores / slashes as word separators.
# We feed detectors an extra delimiter-normalised copy so the same regex
# catches "ignore previous instructions" and "ignore-previous-instructions".
_IDENTIFIER_SURFACES: frozenset[Surface] = frozenset(
    {"branch_name", "tag_name", "file_name", "directory_name", "commit_author"}
)

# Surfaces where ``ward-allow-file:`` directives are honoured. The directive
# is meant for prose contexts (Ward's own README, security-research docs);
# allowing it in commit messages or branch names would let an attacker
# disable detection from inside the very text we're trying to screen.
_SUPPRESSION_SURFACES: frozenset[Surface] = frozenset({"file_content", "code_comment"})


def build_input(surface: Surface, text: str, *, location: str = "") -> ScanInput:
    """Wrap a raw string into a ``ScanInput`` with normalised + decoded forms."""
    if text is None:
        text = ""
    normalised = normalise_text(text)
    decoded = list(decode_candidates(text))
    if surface in _IDENTIFIER_SURFACES:
        identifier_form = split_identifier(normalised)
        if identifier_form != normalised:
            decoded.append(identifier_form)
    # Evasion-resistant forms: leetspeak, character-spacing, repeat-letter.
    # Run rules against the normalised text in each form so we catch
    # "1gn0r3 pr3v10us", "i g n o r e", and "ignooooore".
    for form in evasion_forms(normalised):
        if form not in decoded and form != normalised:
            decoded.append(form)
    suppressed: frozenset[str] = frozenset()
    if surface in _SUPPRESSION_SURFACES:
        suppressed = extract_suppressions(text)
    return ScanInput(
        surface=surface,
        raw=text,
        normalised=normalised,
        decoded=tuple(decoded),
        location=location,
        suppressed_rules=suppressed,
    )


def _is_suppressed(rule_id: str, globs: frozenset[str]) -> bool:
    return any(fnmatchcase(rule_id, glob) for glob in globs)


def scan_inputs(
    inputs: Iterable[ScanInput],
    rule_pack: RulePack,
    *,
    target: str,
    fail_on: Severity = Severity.HIGH,
    threshold: Severity = Severity.LOW,
) -> ScanReport:
    detectors = [cls(rule_pack) for cls in ALL_DETECTOR_CLASSES]
    findings: list[Finding] = []
    for source in inputs:
        for detector in detectors:
            for finding in detector.scan(source):
                if source.suppressed_rules and _is_suppressed(
                    finding.rule_id, source.suppressed_rules
                ):
                    continue
                findings.append(finding)
    return aggregate(findings, target=target, fail_on=fail_on, threshold=threshold)
