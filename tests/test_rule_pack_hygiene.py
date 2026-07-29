"""The rule packs must not contain control characters.

Eight times on this branch a shell heredoc has turned `\\b` in a regex into a
literal backspace byte (0x08) inside a rule pack. Every time, the YAML loader
refused the file and `load_rule_pack` raised - so the failure was loud and the
repair took two minutes.

That is luck, not design. YAML rejects 0x08 specifically; it does NOT reject
every control character, and several would survive the load and silently
change what a pattern matches. `\\f` (0x0C) and `\\v` (0x0B) are both legal
YAML scalar content and both are what `\\f` and `\\v` in a regex become if a
shell eats the backslash - and a pattern containing a literal form feed still
compiles, still loads, and quietly matches nothing.

So this checks the bytes rather than relying on the parser to object.
"""

from __future__ import annotations

import pathlib
import unicodedata

import pytest

RULES = pathlib.Path(__file__).resolve().parents[1] / "src" / "ward" / "rules"

# Tab, newline and carriage return are ordinary YAML. Nothing else is.
ALLOWED_CONTROLS = {0x09, 0x0A, 0x0D}


def rule_files() -> list[pathlib.Path]:
    return sorted(RULES.glob("*.yaml"))


def test_there_are_rule_files() -> None:
    """Without this the sweep below passes over an empty list."""
    assert rule_files(), f"no rule packs found under {RULES}"


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.name)
def test_no_control_characters(path: pathlib.Path) -> None:
    raw = path.read_bytes()
    offenders = [
        (offset, byte)
        for offset, byte in enumerate(raw)
        if byte < 0x20 and byte not in ALLOWED_CONTROLS
    ]
    if offenders:
        offset, byte = offenders[0]
        context = raw[max(0, offset - 60) : offset + 20]
        pytest.fail(
            f"{path.name}: {len(offenders)} control character(s); first is "
            f"0x{byte:02X} at byte {offset}.\n"
            f"  context: {context!r}\n"
            f"  This is almost always a shell heredoc eating a backslash - "
            f"0x08 is `\\b`, 0x0C is `\\f`, 0x0B is `\\v`. Write the edit script "
            f"to a file and run it rather than piping it through a heredoc."
        )


@pytest.mark.parametrize("path", rule_files(), ids=lambda p: p.name)
def test_no_unexpected_invisible_characters(path: pathlib.Path) -> None:
    """A zero-width character inside a pattern changes what it matches.

    The packs deliberately contain plenty of unusual Unicode - homoglyphs,
    bidi controls, the TAG block - but as ESCAPES (`\\u202e`), never as literal
    codepoints. A literal one means an editor or a paste ate something.
    """
    text = path.read_text(encoding="utf-8")
    offenders = sorted({ch for ch in text if unicodedata.category(ch) == "Cf" or ch in "​‌‍﻿"})
    assert not offenders, (
        f"{path.name}: literal invisible characters {[hex(ord(c)) for c in offenders]}. "
        f"Rule packs reference these as escapes, never as codepoints."
    )
