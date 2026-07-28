"""Top-level scan engine. Builds inputs, runs all detectors, aggregates."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from fnmatch import fnmatchcase

from ..detectors import ALL_DETECTOR_CLASSES
from ..detectors.base import Detector
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

# NO CAP ON HOW MANY DECODED PAYLOADS GET THE EVASION TREATMENT.
#
# There was one, of 8, added for performance in the same change that started
# applying evasion transforms to decoded text. It was a bypass: eight decoy
# base64 blobs in front of the real one pushed it past the boundary and the
# payload scanned completely clean. The attacker chooses how many blobs go in
# a PR body, so any positional cap is a cap the attacker controls.
#
# It was not buying anything either. Measured across 0 to 1000 decoy blobs
# (59KB), removing it cost 0.499s -> 0.594s, and total decoded volume is
# already bounded upstream by decode_candidates' byte budget - so this was a
# second bound on something already bounded, in the one form that could be
# stepped over. If the work here ever does need limiting, limit it by total
# volume, never by position in the document.


def build_input(
    surface: Surface,
    text: str,
    *,
    location: str = "",
    trust_suppressions: bool = True,
    suppress_rules: tuple[str, ...] | None = None,
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
    decoded: list[str] = []

    def _add(form: str) -> None:
        if form and form != normalised and form not in decoded:
            decoded.append(form)

    decoded_payloads: list[str] = []
    for form in decode_candidates(text):
        _add(form)
        decoded_payloads.append(form)
    # Also decode the NORMALISED text. A single zero-width character dropped
    # inside a base64 or hex blob makes the raw text undecodable, so scanning
    # only the raw form meant one invisible character was enough to stop the
    # payload ever being decoded and rescanned.
    if normalised != text:
        for form in decode_candidates(normalised):
            _add(form)
            decoded_payloads.append(form)

    # Text forms the evasion transforms should be applied to. Identifier
    # surfaces get both, because git forbids spaces in ref names: any
    # multi-word instruction in a branch, tag or file name MUST use
    # delimiters, so delimiter-splitting and leetspeak/repeat-letter evasion
    # are the natural combination on Ward's flagship surface. Running the
    # evasion transforms over the normalised text alone left
    # "1gn0r3-4ll-pr3v10us-1nstruct10ns" undetected: splitting leaves it leet,
    # and de-leeting leaves it hyphenated, so neither product matched.
    evasion_bases = [normalised]
    if surface in _IDENTIFIER_SURFACES:
        identifier_form = split_identifier(normalised)
        if identifier_form != normalised:
            _add(identifier_form)
            evasion_bases.append(identifier_form)

    # A DECODED PAYLOAD IS STILL ATTACKER-CONTROLLED TEXT, so it gets the same
    # treatment as the surface text rather than being matched only as-is.
    # Decoding used to be the end of the line: base64 of plain English was
    # caught, but base64 of the SAME sentence in leetspeak, or with a Cyrillic
    # homoglyph, or hyphenated instead of spaced, all scanned clean. Each was
    # a one-step bypass built by composing two techniques Ward already
    # detected individually.
    #
    # Hyphenation is the important one. git forbids spaces in ref names, so
    # any multi-word payload in a branch name MUST be delimited - which meant
    # base64 of a branch-shaped payload was the natural encoding to reach for
    # and the one guaranteed to get through.
    for payload in decoded_payloads:
        split_payload = split_identifier(payload)
        if split_payload != payload:
            _add(split_payload)
            evasion_bases.append(split_payload)
        evasion_bases.append(payload)

    # Unicode TAG-block decode runs on the RAW text (normalise strips those
    # chars). Any TAG-smuggled instruction reappears as visible ASCII so the
    # standard rules match against it.
    tag_decoded = decode_unicode_tags(text)
    if tag_decoded != text:
        _add(tag_decoded)

    # Evasion-resistant forms: leetspeak, character-spacing, repeat-letter.
    # Run rules against each base form so we catch "1gn0r3 pr3v10us",
    # "i g n o r e", and "ignooooore".
    for base in evasion_bases:
        for form in evasion_forms(base):
            _add(form)
    suppressed: frozenset[str] = frozenset()
    if trust_suppressions and surface in _SUPPRESSION_SURFACES:
        suppressed = extract_suppressions(text)
    if suppress_rules:
        # Caller-supplied, not attacker-supplied: used for alternate decodings
        # of a file, where a character-level finding would be an artefact of
        # the re-decode rather than something present in the document.
        suppressed = suppressed | frozenset(suppress_rules)
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


class UnknownCategoryError(ValueError):
    """A rule declares a category no detector will ever run."""


def check_rule_categories(rule_pack: RulePack) -> None:
    """Public entry point for the orphan-rule check. Raises on a bad pack."""
    _check_every_rule_runs(rule_pack, [cls(rule_pack) for cls in ALL_DETECTOR_CLASSES])


def _check_every_rule_runs(rule_pack: RulePack, detectors: Sequence[Detector]) -> None:
    """Refuse a pack containing rules that nothing will execute.

    Detectors select their rules with ``by_category``, which returns an empty
    tuple for a category no detector claims. So a custom rule whose category
    is misspelled - ``instruction-override`` for ``instruction_override``, one
    hyphen - loaded without complaint, matched nothing, and Ward reported PASS.

    The author had written a CRITICAL rule, watched it install cleanly, and
    got a green tick on the exact payload it was written to catch. That is the
    worst way for a security tool to fail, so it is an error rather than a
    warning: a rule that cannot run is indistinguishable from no rule at all,
    and the whole point of a custom pack is that someone is relying on it.
    """
    known = {d.category for d in detectors}
    orphans = sorted({r.id: r.category for r in rule_pack.rules if r.category not in known}.items())
    if not orphans:
        return
    listed = ", ".join(f"{rule_id} (category {category!r})" for rule_id, category in orphans)
    raise UnknownCategoryError(
        f"{len(orphans)} rule(s) declare a category no detector runs, so they would "
        f"never fire and the scan would report PASS regardless of the input: {listed}. "
        f"Known categories: {', '.join(sorted(known))}."
    )


def scan_inputs(
    inputs: Iterable[ScanInput],
    rule_pack: RulePack,
    *,
    target: str,
    fail_on: Severity = Severity.HIGH,
    threshold: Severity = Severity.LOW,
) -> ScanReport:
    detectors = [cls(rule_pack) for cls in ALL_DETECTOR_CLASSES]
    _check_every_rule_runs(rule_pack, detectors)
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
