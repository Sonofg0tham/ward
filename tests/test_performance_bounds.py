"""Superlinear paths are a fail-open: a scanner that hangs gets removed.

Every case here was measured growing faster than linearly against input an
attacker chooses freely, and each one is well inside GitHub's 65,536-character
PR-body limit at the point it becomes painful.

The assertions are generous - several times the measured fixed timing - so
they fail on a return of quadratic behaviour rather than on a slow CI runner.
"""

from __future__ import annotations

import base64
import re
import time

import pytest

from ward.core.engine import build_input


def _elapsed(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


def test_a_fenced_system_block_does_not_backtrack(rule_pack) -> None:
    """``\\s*`` around the fences matched newlines.

    So the closing fence could consume an arbitrary run of blank lines while
    the lazy body tried every length against each of them. ```` ```system ````
    plus 3,000 blank lines - 2KB - took 6s, and 6KB took 28s.
    """
    pattern = next(
        p
        for rule in rule_pack.rules
        if rule.id == "io.markdown_code_fence_system"
        for p in rule.patterns
    )
    text = "```system\n" + "\n" * 6000
    assert _elapsed(lambda: pattern.search(text)) < 2.0


def test_an_allow_file_directive_with_a_long_run_of_spaces(rule_pack) -> None:
    """A lazy capture followed by ``\\s*`` and an ``$`` alternation was cubic.

    "# ward-allow-file:" plus 1,600 spaces - a 1.6KB line - took 7.7s inside
    build_input, and 3.2KB took about a minute.
    """
    from ward.core.normalise import extract_suppressions

    text = "# ward-allow-file:" + " " * 3200 + "-"
    assert _elapsed(lambda: extract_suppressions(text)) < 2.0


def test_a_readme_full_of_image_syntax(rule_pack) -> None:
    """Unbounded ``[^\\]]*`` scanned to end-of-document per "![".

    200KB of repeated "![" cost 14.6s in scan-local. A README full of image
    syntax is an entirely ordinary file.
    """
    pattern = next(
        p
        for rule in rule_pack.rules
        if rule.id == "exf.markdown_image_callback"
        for p in rule.patterns
    )
    text = "![" * 100_000
    assert _elapsed(lambda: pattern.search(text)) < 2.0


def test_building_an_input_full_of_blobs_is_not_quadratic() -> None:
    """``form not in decoded`` on a LIST is a linear scan, once per form.

    A 156KB PR body of distinct base64 blobs spent 7.4s inside build_input
    alone, against 0.045s for 100KB of ordinary prose. A set beside the list
    keeps the ordering the evidence reporting needs.
    """
    text = " ".join(base64.b64encode(f"pay-{i:014d}".encode()).decode() for i in range(6400))
    assert len(text) > 150_000
    assert _elapsed(lambda: build_input("pr_body", text, location="f")) < 3.0


@pytest.mark.parametrize(
    ("label", "build"),
    [
        ("unclosed tool tags", lambda: "<tool_call>" * 40_000),
        ("spaced letters", lambda: "i g n o r e  " * 8000),
        ("invisible soup", lambda: "a\u200b" * 50_000),
        ("hex soup", lambda: "deadbeef" * 12_800),
    ],
)
def test_adversarial_shapes_stay_linear(label: str, build) -> None:
    """A broad sweep, so a new rule cannot quietly reintroduce a hang."""
    text = build()
    assert len(text) >= 100_000, "the fixture must be large enough to expose growth"
    assert _elapsed(lambda: build_input("pr_body", text, location="f")) < 5.0, (
        f"{label} took too long at {len(text) // 1024}KB"
    )


def test_every_bundled_pattern_survives_its_own_worst_case(rule_pack) -> None:
    """Each pattern against input built to punish its own structure.

    Cheap insurance: the widened qualifier runs are ``(?:(?:a|b|c)\\s+)*``,
    the classic catastrophic-backtracking shape. They are safe because each
    alternative is a distinct literal followed by ``\\s+``, so there is only
    one way to match at any position - but that is a property worth checking
    rather than assuming.
    """
    shapes = [
        "ignore " + "all " * 400 + "X",
        "disregard " + "other " * 400 + "X",
        "print your " + "hidden " * 400 + "X",
        "ignore" + " " * 2000 + "X",
        "ig" + "n" * 2000 + "ore all previous instructions",
        "```system\n" + "\n" * 2000,
    ]
    slow: list[str] = []
    for rule in rule_pack.rules:
        for pattern in rule.patterns:
            for shape in shapes:
                if _elapsed(lambda p=pattern, s=shape: p.search(s)) > 0.5:
                    slow.append(f"{rule.id}: {pattern.pattern[:60]}")
    assert not slow, "patterns slower than 0.5s on adversarial input: " + "; ".join(slow[:5])


def test_no_pattern_uses_whitespace_star_after_a_newline(rule_pack) -> None:
    """``\\n\\s*`` is the shape behind two separate hangs in this codebase.

    ``\\s`` matches the newline itself, so the group re-consumes line breaks
    the anchor already matched and the engine explores every division of a run
    of blank lines. Both times it was found by profiling rather than review,
    so it is worth a structural check.
    """
    offenders = [
        f"{rule.id}: {p.pattern[:70]}"
        for rule in rule_pack.rules
        for p in rule.patterns
        if re.search(r"\\n\\s\*", p.pattern) or re.search(r"\\r\?\\n\\s\*", p.pattern)
    ]
    assert not offenders, "use [ \\t]* after a newline, not \\s*: " + "; ".join(offenders)
