"""Text normalisation helpers.

Most detectors operate on the *normalised* form of text: NFKC unicode form
with zero-width characters stripped. The *raw* form is preserved separately
so that obfuscation detectors can spot the very characters we stripped here.

Base64 and hex blocks that look long enough to hide a payload are also
unwrapped so other detectors can scan the decoded content.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

# Zero-width and direction-override characters commonly used to hide payloads.
_INVISIBLE_CHARS = {
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "﻿",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "᠎",  # MONGOLIAN VOWEL SEPARATOR
    "‪",  # LEFT-TO-RIGHT EMBEDDING
    "‫",  # RIGHT-TO-LEFT EMBEDDING
    "‬",  # POP DIRECTIONAL FORMATTING
    "‭",  # LEFT-TO-RIGHT OVERRIDE
    "‮",  # RIGHT-TO-LEFT OVERRIDE
    "⁦",  # LEFT-TO-RIGHT ISOLATE
    "⁧",  # RIGHT-TO-LEFT ISOLATE
    "⁨",  # FIRST STRONG ISOLATE
    "⁩",  # POP DIRECTIONAL ISOLATE
}

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{80,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{80,})(?![0-9a-fA-F])")

# Identifier surfaces use these characters where natural language uses spaces.
# Branch names, file paths, and tag names all use hyphens, underscores, dots,
# and slashes as word separators. Normalising them to spaces lets the same
# regex rule fire against "ignore previous instructions" in a PR body and
# "ignore-previous-instructions" in a branch name.
_IDENTIFIER_DELIM_RE = re.compile(r"[\-_/\.\\]+")

# Leetspeak substitution table. Applied as a coarse alternative form of the
# text so existing regex rules light up against "1gn0r3 pr3v10us".
_LEET_TABLE = str.maketrans(
    {
        "1": "i",
        "!": "i",
        "|": "i",
        "0": "o",
        "3": "e",
        "€": "e",
        "4": "a",
        "@": "a",
        "5": "s",
        "$": "s",
        "7": "t",
        "+": "t",
        "9": "g",
        "8": "b",
    }
)

# Detects single tokens of the shape "i.g.n.o.r.e" or "i-g-n-o-r-e" where
# letters are separated by a consistent non-space separator. We handle the
# intra-word-separator case (the realistic evasion form) but deliberately
# skip the all-single-spaces case ("i g n o r e p r e v i o u s") because
# word boundaries are then truly ambiguous - that's a known limitation
# documented in the README.
_INTRA_WORD_SPACED_RE = re.compile(r"\b[A-Za-z](?:[\.\-_·][A-Za-z]){2,}\b")

# Collapses long runs of the same letter. We produce two variants so common
# English doubled letters are preserved in at least one of them:
#   collapse-to-1: "ignooooore" -> "ignore"   (loses "all" -> "al")
#   collapse-to-2: "alllll" -> "all"          (keeps "ignooore" -> "ignoore")
# Rules light up against whichever variant survives the collapse intact.
_REPEAT_RE_TO_ONE = re.compile(r"([A-Za-z])\1{2,}")
_REPEAT_RE_TO_TWO = re.compile(r"([A-Za-z])\1{3,}")


def strip_invisible(text: str) -> str:
    """Remove zero-width and bidi-override characters."""
    return "".join(ch for ch in text if ch not in _INVISIBLE_CHARS)


def normalise_text(text: str) -> str:
    """NFKC-normalise and strip invisible characters.

    Suitable for feeding to regex-based detectors that want to ignore visual
    obfuscation. Use ``contains_invisible`` against the raw text first if you
    want to flag the obfuscation itself.
    """
    nfkc = unicodedata.normalize("NFKC", text)
    return strip_invisible(nfkc)


def contains_invisible(text: str) -> list[tuple[int, str, str]]:
    """Return positions of invisible characters as (index, char, codepoint)."""
    hits: list[tuple[int, str, str]] = []
    for idx, ch in enumerate(text):
        if ch in _INVISIBLE_CHARS:
            hits.append((idx, ch, f"U+{ord(ch):04X}"))
    return hits


_WARD_ALLOW_RE = re.compile(
    r"(?:<!--|//|#|/\*)\s*ward-allow-file\s*:\s*([^\n\->]+?)\s*(?:-->|\*/|$)",
    re.MULTILINE,
)


def extract_suppressions(text: str) -> frozenset[str]:
    """Pull out ``ward-allow-file: <rule-glob>, ...`` directives from text.

    Supports HTML comments (``<!-- ... -->``), C-style block comments
    (``/* ... */``), and hash / double-slash line comments. Globs are
    fnmatch-style, so ``io.*`` matches every rule whose id starts with
    ``io.``.
    """
    rules: set[str] = set()
    for match in _WARD_ALLOW_RE.finditer(text):
        raw = match.group(1)
        for token in raw.split(","):
            token = token.strip()
            if token:
                rules.add(token)
    return frozenset(rules)


def split_identifier(text: str) -> str:
    """Replace identifier delimiters with spaces.

    Use for surfaces like branch names, file names, and tag names where
    hyphen / underscore / slash / dot stand in for spaces.
    """
    return _IDENTIFIER_DELIM_RE.sub(" ", text)


def deleet(text: str) -> str:
    """Apply a coarse leetspeak transliteration.

    Replaces common digit / symbol substitutions with their letter
    equivalents (1->i, 0->o, 3->e, @->a, etc). The result is used as an
    alternative form for detector matching, not as a replacement for the
    real text. Even if natural text contains digits ("Python 3.11"), the
    deleet form ("Python e.ii") won't match any attack rule, so the false-
    positive cost is essentially nil.
    """
    return text.translate(_LEET_TABLE)


def decompose_spaced_runs(text: str) -> str:
    """Collapse intra-word character-spacing evasion.

    "i.g.n.o.r.e p.r.e.v.i.o.u.s instructions" -> "ignore previous instructions"
    "i-g-n-o-r-e all p-r-e-v-i-o-u-s"          -> "ignore all previous"

    The all-single-spaces case ("i g n o r e p r e v i o u s") is NOT
    handled here because word boundaries cannot be recovered reliably.
    """
    def _collapse(match: re.Match[str]) -> str:
        return re.sub(r"[\.\-_·]", "", match.group(0))

    return _INTRA_WORD_SPACED_RE.sub(_collapse, text)


def collapse_repeats(text: str, *, max_run: int = 1) -> str:
    """Fold runs of repeated letters.

    With ``max_run=1`` (default) any run of 3+ identical letters collapses
    to one ("ignooooore" -> "ignore"). With ``max_run=2`` only runs of 4+
    collapse, and they collapse to two ("alllll" -> "all"), preserving
    naturally-doubled English letters.
    """
    if max_run == 1:
        return _REPEAT_RE_TO_ONE.sub(r"\1", text)
    if max_run == 2:
        return _REPEAT_RE_TO_TWO.sub(r"\1\1", text)
    raise ValueError(f"max_run must be 1 or 2 (got {max_run})")


def evasion_forms(text: str) -> list[str]:
    """Build alternative forms of the text for evasion-resistant matching.

    Returns a list of additional strings that detectors should run their
    rules against in addition to the normal NFKC-normalised form. Each
    form targets one common evasion technique. Forms identical to the
    input or duplicated by another form are filtered out.
    """
    forms: list[str] = []
    seen: set[str] = {text}

    def _add(candidate: str) -> None:
        if candidate not in seen:
            seen.add(candidate)
            forms.append(candidate)

    _add(deleet(text))
    _add(decompose_spaced_runs(text))
    _add(collapse_repeats(text, max_run=1))
    _add(collapse_repeats(text, max_run=2))
    # Combined transform: deleet -> decompose -> collapse-to-1. Catches
    # "1.g.n.0.r.3 4lllll pr3v10us" style stacked evasion.
    _add(collapse_repeats(decompose_spaced_runs(deleet(text)), max_run=1))
    _add(collapse_repeats(decompose_spaced_runs(deleet(text)), max_run=2))
    return forms


def decode_candidates(text: str) -> list[str]:
    """Find long base64 / hex blocks and return their decoded UTF-8 forms.

    Decode failures are dropped silently; this is a best-effort step to give
    downstream detectors more surface area to match against.
    """
    decoded: list[str] = []
    for match in _BASE64_RE.finditer(text):
        blob = match.group(1)
        try:
            payload = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded.append(payload.decode("utf-8", errors="strict"))
        except UnicodeDecodeError:
            continue
    for match in _HEX_RE.finditer(text):
        blob = match.group(1)
        if len(blob) % 2 != 0:
            continue
        try:
            payload = bytes.fromhex(blob)
        except ValueError:
            continue
        try:
            decoded.append(payload.decode("utf-8", errors="strict"))
        except UnicodeDecodeError:
            continue
    return decoded
