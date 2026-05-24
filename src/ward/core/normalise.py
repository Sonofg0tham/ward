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
