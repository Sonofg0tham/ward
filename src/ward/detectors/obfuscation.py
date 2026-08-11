"""Detects obfuscation: invisible chars, RTL overrides, long encoded blobs,
mixed-script homoglyphs."""

from __future__ import annotations

import re
import unicodedata

from ..core.models import Finding, ScanInput, Severity
from ..core.normalise import contains_unicode_tag, is_invisible
from .base import RuleBasedDetector, truncate_evidence

_BASE64_BLOCK = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_BLOCK = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{80,}(?![0-9a-fA-F])")

# Surfaces where a long base64/hex string is almost certainly suspicious.
# We exclude file_content because legitimate Markdown / source files often
# embed encoded assets.
_SUSPECT_SURFACES_FOR_ENCODED = frozenset(
    {
        "branch_name",
        "tag_name",
        "commit_message",
        "file_name",
        "directory_name",
        "pr_title",
        "pr_body",
        "issue_title",
        "issue_body",
        "code_comment",
        "stdin",
    }
)

# Bidi / direction override characters. Listed individually so we can report
# exactly which one fired.
_BIDI_CONTROLS = {
    "‪": "LEFT-TO-RIGHT EMBEDDING",
    "‫": "RIGHT-TO-LEFT EMBEDDING",
    "‬": "POP DIRECTIONAL FORMATTING",
    "‭": "LEFT-TO-RIGHT OVERRIDE",
    "‮": "RIGHT-TO-LEFT OVERRIDE",
    "⁦": "LEFT-TO-RIGHT ISOLATE",
    "⁧": "RIGHT-TO-LEFT ISOLATE",
    "⁨": "FIRST STRONG ISOLATE",
    "⁩": "POP DIRECTIONAL ISOLATE",
    # U+200E LEFT-TO-RIGHT MARK and U+200F RIGHT-TO-LEFT MARK are deliberately
    # NOT here. They are the ordinary way to keep a version number or a Latin
    # word rendering correctly inside Arabic or Hebrew prose, so reporting them
    # turns any legitimate RTL README into a HIGH finding and a hard FAIL.
    # They are still stripped by normalise (is_invisible catches them as Cf),
    # so "ig<LRM>nore all previous instructions" still fires io.ignore_previous
    # - the payload is caught, the innocent document is not punished.
}

_ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "᠎": "MONGOLIAN VOWEL SEPARATOR",
    "­": "SOFT HYPHEN",
    "⁡": "FUNCTION APPLICATION",
    "⁢": "INVISIBLE TIMES",
    "⁣": "INVISIBLE SEPARATOR",
    "⁤": "INVISIBLE PLUS",
    # VARIATION SELECTOR-15/16 are deliberately NOT here. U+FE0F is what makes
    # an emoji render in colour, so reporting it flags "fix: retry backoff
    # (behaviour change) ⚠️" - Ward's own commit history trips it. They are
    # still stripped by the normaliser, so they cannot be used to split a word.
}

# The named table above is a convenience for the human-readable label, not the
# detection set. It had drifted from ``is_invisible``, which is what the
# NORMALISER strips - so U+061C ARABIC LETTER MARK, U+200E LEFT-TO-RIGHT MARK
# and U+FFF9 were removed from the text and then reported by nobody. Silently
# repairing a character an attacker inserted, and saying nothing, is the worst
# of both behaviours: the payload is reassembled for matching but the evidence
# that someone tried to hide it is thrown away.
_ZERO_WIDTH_FALLBACK_LABEL = "invisible formatting character"

# EVERY invisible character's innocence depends on what it sits BETWEEN. This
# used to be a set - ZWJ, ZWNJ, LRM, RLM - because those are the ones required
# in Persian, Arabic, Hindi and Indic scripts, and the ones that bind a
# multi-part emoji together, so flagging them outright failed a build on
# completely legitimate text:
#   Fix the login retry loop 👨‍💻
#   رفع می‌شود
#
# Naming the four was the same mistake this project keeps making in its rule
# packs: an enumerated list of the cases someone thought of. U+200B was not on
# it, and U+200B is what Dependabot puts in front of every username it credits.
# The test now lives in _first_invisible and applies to all of them - see its
# docstring. What makes an invisible character suspicious is splitting a Latin
# word, where it has no linguistic function and the only reason to insert one
# is to break the word up ("ig<ZWJ>nore all previous instructions"), or
# appearing in a run, which is the shape of hidden content.

# Never reported, whatever their category. The variation selectors are what
# make an emoji render in colour, so reporting them fails a build on "fix:
# retry backoff (behaviour change) ⚠️" - Ward's own commit history trips it.
# The normaliser still strips them, so they cannot be used to split a word.
_KEEP_VISIBLE = frozenset({chr(cp) for cp in range(0xFE00, 0xFE10)})


class ObfuscationDetector(RuleBasedDetector):
    """Pattern-rule scan plus heuristics that need access to the raw text."""

    name = "obfuscation"
    category = "obfuscation"
    matches_against = "raw"

    def scan(self, source: ScanInput) -> list[Finding]:
        findings = list(super().scan(source))
        findings.extend(self._heuristics(source))
        findings.extend(self._mixed_script(source))
        return findings

    def _mixed_script(self, source: ScanInput) -> list[Finding]:
        """Flag tokens that mix Latin with a confusable script.

        Cyrillic ``і`` (U+0456) looks identical to Latin ``i`` but is treated
        as a different character by any Latin-only regex. We flag tokens that
        mix Latin with one of the scripts that contain Latin-lookalike
        glyphs (Cyrillic, Greek, Armenian, Hebrew).

        Crucially we do NOT flag Latin+CJK or Latin+Arabic because those
        scripts don't have visually confusable letters with Latin, and
        legitimate text routinely mixes English acronyms into CJK / Arabic
        prose.
        """
        hits: list[Finding] = []
        for match in _WORD_RE.finditer(source.raw):
            token = match.group(0)
            if len(token) < 4:
                continue
            script_counts: dict[str, int] = {}
            for ch in token:
                if not ch.isalpha():
                    continue
                script = _script_of(ch)
                if script is None:
                    continue
                script_counts[script] = script_counts.get(script, 0) + 1
            confusables = {s for s in script_counts if s in _CONFUSABLE_WITH_LATIN}
            if not confusables or "latin" not in script_counts:
                continue
            # Require at least one Latin and one confusable character in the
            # same token. A single Cyrillic letter glued onto a long Latin
            # word is the canonical homoglyph attack.
            if script_counts["latin"] < 1 or any(script_counts[s] < 1 for s in confusables):
                continue
            other = sorted(confusables)
            hits.append(
                Finding(
                    rule_id="obf.mixed_script",
                    detector=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    message=(
                        f"Token {token!r} mixes Latin with {', '.join(other)} "
                        "(possible homoglyph attack)"
                    ),
                    surface=source.surface,
                    location=source.location,
                    evidence=truncate_evidence(source.raw, match.span()),
                    remediation=(
                        "Reject. Normalise the text and require a human review. "
                        "Words that mix Latin and a confusable script visually "
                        "impersonate English."
                    ),
                    references=("https://www.unicode.org/reports/tr39/",),
                )
            )
            # One mixed-script word per surface is enough to flag the input.
            break
        return hits

    def _heuristics(self, source: ScanInput) -> list[Finding]:
        results: list[Finding] = []
        raw = source.raw

        bidi_hit = _first_match_of(raw, _BIDI_CONTROLS)
        if bidi_hit is not None:
            idx, ch, label = bidi_hit
            results.append(
                Finding(
                    rule_id="obf.bidi_override",
                    detector=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    message=f"Bidirectional override character ({label}) found in {source.surface}",
                    surface=source.surface,
                    location=source.location,
                    evidence=f"U+{ord(ch):04X} at offset {idx}",
                    remediation="Reject the metadata; bidi overrides can hide malicious instructions in plain sight.",
                    references=("https://trojansource.codes/",),
                )
            )

        zw_hit = _first_invisible(raw)
        if zw_hit is not None:
            idx, ch, label = zw_hit
            results.append(
                Finding(
                    rule_id="obf.zero_width",
                    detector=self.name,
                    category=self.category,
                    severity=Severity.MEDIUM,
                    message=f"Zero-width character ({label}) found in {source.surface}",
                    surface=source.surface,
                    location=source.location,
                    evidence=f"U+{ord(ch):04X} at offset {idx}",
                    remediation="Strip the character. Treat the source as suspicious until reviewed by a human.",
                )
            )

        tag_hits = contains_unicode_tag(raw)
        if tag_hits:
            idx, cp_label = tag_hits[0]
            results.append(
                Finding(
                    rule_id="obf.unicode_tag",
                    detector=self.name,
                    category=self.category,
                    severity=Severity.HIGH,
                    message=(
                        f"Unicode TAG-block characters ({len(tag_hits)} total) found in "
                        f"{source.surface}. TAG chars are invisible to humans but readable "
                        "by LLM tokenisers - a documented smuggling channel."
                    ),
                    surface=source.surface,
                    location=source.location,
                    evidence=f"{cp_label} at offset {idx} (+{len(tag_hits) - 1} more)",
                    remediation="Strip the TAG-block range (U+E0000-U+E007F) before feeding text to any agent.",
                    references=(
                        "https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/",
                    ),
                )
            )

        if source.surface in _SUSPECT_SURFACES_FOR_ENCODED:
            for match in _BASE64_BLOCK.finditer(raw):
                results.append(
                    Finding(
                        rule_id="obf.base64_blob",
                        detector=self.name,
                        category=self.category,
                        severity=Severity.MEDIUM,
                        message=(
                            f"Long base64 block ({match.end() - match.start()} chars) in "
                            f"{source.surface} - unusual location for encoded data"
                        ),
                        surface=source.surface,
                        location=source.location,
                        evidence=truncate_evidence(raw, match.span()),
                        remediation="Decode the blob and review its content before letting an agent ingest it.",
                    )
                )
                break  # one blob is enough to flag the surface
            for match in _HEX_BLOCK.finditer(raw):
                results.append(
                    Finding(
                        rule_id="obf.hex_blob",
                        detector=self.name,
                        category=self.category,
                        severity=Severity.LOW,
                        message=(
                            f"Long hex block ({match.end() - match.start()} chars) in "
                            f"{source.surface} - unusual location for encoded data"
                        ),
                        surface=source.surface,
                        location=source.location,
                        evidence=truncate_evidence(raw, match.span()),
                        remediation="Decode the blob and review its content before letting an agent ingest it.",
                    )
                )
                break

        return results


def _first_match_of(text: str, table: dict[str, str]) -> tuple[int, str, str] | None:
    for idx, ch in enumerate(text):
        if ch in table:
            return idx, ch, table[ch]
    return None


def _is_latin_letter(ch: str) -> bool:
    return ("a" <= ch <= "z") or ("A" <= ch <= "Z")


def _first_invisible(text: str) -> tuple[int, str, str] | None:
    """First invisible character that actually does something.

    Driven by ``is_invisible`` rather than by the named table, so every
    character the normaliser strips is also one the scan can report. The named
    table only supplies a nicer label when it has one.

    The presence of an invisible character is not by itself evidence of
    anything, and reporting it as though it were flagged EVERY DEPENDABOT PR
    ON GITHUB. Dependabot writes ``<code>@`` + U+200B + username in its
    release-note credits so the mention does not notify the person; a routine
    version bump therefore arrived carrying eleven zero-width spaces and came
    back WARN. On this project's own terms that is the worse half of the
    trade - a gate that flags every dependency update is a gate somebody turns
    off, and then its recall is zero.

    So the test is what the character DOES, which is not something an attacker
    can choose favourably, rather than which character it is:

    * It splits a Latin word. ``ig`` + U+00AD + ``nore`` defeats ``\\bignore\\b``
      while reading as "ignore" to a human. Splitting a token IS the evasion,
      so an attacker cannot avoid this test and still evade anything.
    * It sits in a run of two or more. One invisible character carries no
      payload; a sequence of them is the shape of hidden or encoded content,
      and it is why ``06_pr_body_zero_width`` is a run rather than a single.

    Anything else is inert: it does not break a token, so every content rule
    still sees the words, and the normaliser strips it before the derived-form
    scan regardless. This generalises the rule that used to apply only to
    ``_CONTEXT_DEPENDENT`` - joiners were already exempt when not between
    Latin letters, because Persian and Indic put them between non-Latin
    characters by design. That reasoning was never specific to joiners.

    Not covered, deliberately: many isolated inert characters spread thinly
    enough to encode data by position. Catching that needs a density
    threshold, and a threshold is a number the attacker reads off the source
    and stays under - the same mistake as an enumerated word list. Such a
    channel is also invisible to the model it would target, which strips
    these characters before tokenising.
    """

    def hidden(i: int) -> bool:
        """Invisible, and not a variation selector we deliberately keep."""
        if not 0 <= i < len(text):
            return False
        ch = text[i]
        return is_invisible(ch) and ch not in _KEEP_VISIBLE

    for idx, ch in enumerate(text):
        if not hidden(idx):
            continue
        # A run of two or more. Computed over the same set `hidden` uses, so a
        # variation selector does not count towards it - otherwise the U+FE0F
        # + U+200D in an ordinary emoji sequence (the rainbow flag is exactly
        # this) would read as a run and every emoji in a PR title would flag.
        if hidden(idx - 1) or hidden(idx + 1):
            return idx, ch, _ZERO_WIDTH.get(ch, _ZERO_WIDTH_FALLBACK_LABEL)
        before = text[idx - 1] if idx else ""
        after = text[idx + 1] if idx + 1 < len(text) else ""
        if _is_latin_letter(before) and _is_latin_letter(after):
            return idx, ch, _ZERO_WIDTH.get(ch, _ZERO_WIDTH_FALLBACK_LABEL)
    return None


# Word tokeniser for the mixed-script check. Splits on whitespace and most
# punctuation but treats any letter (any script) as part of a word.
_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)

# Scripts that share visually confusable glyphs with Latin. CJK and Arabic
# are deliberately excluded: legitimate Chinese / Japanese / Korean / Arabic
# text often embeds English acronyms (PR, API, URL), and CJK characters do
# not impersonate Latin letters.
_CONFUSABLE_WITH_LATIN = frozenset({"cyrillic", "greek", "armenian", "hebrew"})


def _script_of(ch: str) -> str | None:
    """Return a coarse script name for a single character.

    Uses ``unicodedata.name`` rather than a hand-rolled block table so we
    inherit Unicode updates automatically. Returns ``None`` for characters
    whose name lookup fails.
    """
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    if name.startswith("LATIN"):
        return "latin"
    if name.startswith("CYRILLIC"):
        return "cyrillic"
    if name.startswith("GREEK"):
        return "greek"
    if name.startswith("ARMENIAN"):
        return "armenian"
    if name.startswith("ARABIC"):
        return "arabic"
    if name.startswith("HEBREW"):
        return "hebrew"
    if name.startswith(("CJK", "HIRAGANA", "KATAKANA", "HANGUL")):
        return "cjk"
    return "common"
