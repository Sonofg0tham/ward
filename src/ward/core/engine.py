"""Top-level scan engine. Builds inputs, runs all detectors, aggregates."""

from __future__ import annotations

from collections.abc import Iterable
from fnmatch import fnmatchcase

from ..detectors import ALL_DETECTOR_CLASSES
from .models import Finding, ScanInput, ScanReport, Severity, Surface
from .normalise import (
    decode_candidates,
    decode_unicode_tags,
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

# Surfaces where ``ward-allow-file:`` directives are honoured.
#
# Only ``file_content``. Source-file top-of-file comments are deliberately
# excluded because they are an attacker-controlled surface in any threat
# model where a PR can introduce new files: a malicious PR could add a
# ``.py`` whose first line is ``# ward-allow-file: *`` and silence every
# rule against that file. Restricting suppression to ``file_content`` means
# the directive must live in a documentation file (.md / .rst / .txt /
# .adoc per scan-local's DOC_SUFFIXES), where a PR-introduced change is
# visible to a human reviewer.
#
# This is still not a full provenance check; an attacker who can modify
# an existing doc file (eg README.md) in a PR can suppress detection on
# that file. The mitigation is operational: review .md changes carefully,
# and prefer a single repo-root ``.wardignore`` for path-scoped
# suppression that does not flow through scan content at all.
_SUPPRESSION_SURFACES: frozenset[Surface] = frozenset({"file_content"})


def build_input(
    surface: Surface,
    text: str,
    *,
    location: str = "",
    trust_suppressions: bool = True,
) -> ScanInput:
    """Wrap a raw string into a ``ScanInput`` with normalised + decoded forms.

    ``trust_suppressions`` gates whether ``ward-allow-file`` directives in the
    text are honoured. Set it to False for content whose provenance is
    untrusted (e.g. a file changed by the current PR): the directive is then
    ignored so an attacker cannot suppress detection by editing a doc file.
    """
    if text is None:
        text = ""
    normalised = normalise_text(text)
    decoded = list(decode_candidates(text))
    if surface in _IDENTIFIER_SURFACES:
        identifier_form = split_identifier(normalised)
        if identifier_form != normalised:
            decoded.append(identifier_form)
    # Unicode TAG-block decode runs on the RAW text (normalise strips those
    # chars). Any TAG-smuggled instruction reappears as visible ASCII so the
    # standard rules match against it.
    tag_decoded = decode_unicode_tags(text)
    if tag_decoded != text and tag_decoded != normalised:
        decoded.append(tag_decoded)
    # Evasion-resistant forms: leetspeak, character-spacing, repeat-letter.
    # Run rules against the normalised text in each form so we catch
    # "1gn0r3 pr3v10us", "i g n o r e", and "ignooooore".
    for form in evasion_forms(normalised):
        if form not in decoded and form != normalised:
            decoded.append(form)
    suppressed: frozenset[str] = frozenset()
    if trust_suppressions and surface in _SUPPRESSION_SURFACES:
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
