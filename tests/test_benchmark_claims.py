"""The benchmark figures in the README must be the ones the tool reports.

The README claimed 55.5% full-corpus recall while `ward bench` reported
54.2%. Nobody had re-run it after a round of rule work, so the headline
number in a detection tool's README was wrong - and wrong in the flattering
direction, which is the version that matters.

Only the SMOKE figure is pinned here. It runs against the 50-row samples
bundled in the wheel, so it is offline, deterministic and safe in CI. The
full-corpus numbers need a download of several thousand rows and cannot be
asserted in a unit test; the guard for those is that this file exists and
prompts a re-measure whenever the smoke number moves.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from ward.bench.runner import run_benchmark

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"


@pytest.fixture(scope="module")
def smoke():
    """The benchmark against the bundled samples only - no download, no cache."""
    return run_benchmark(use_cache=False)


def test_readme_smoke_recall_matches_the_tool(smoke) -> None:
    recall = smoke.overall_recall
    assert recall is not None, "the smoke benchmark scored zero in-scope rows"

    text = README.read_text(encoding="utf-8")
    match = re.search(r"bundled 50-row samples[^)]*\):\s*([0-9]+\.[0-9])% in-scope recall", text)
    assert match, "the README no longer states a smoke recall figure in the expected shape"
    claimed = float(match.group(1))
    actual = round(recall * 100, 1)
    assert claimed == actual, (
        f"README claims {claimed}% smoke recall, the tool reports {actual}%. "
        "Re-run `ward bench` and update README.md and CHANGELOG.md together - "
        "a headline number nobody re-measured is how the last one drifted."
    )


def test_readme_smoke_fpr_matches_the_tool(smoke) -> None:
    fpr = smoke.overall_false_positive_rate
    assert fpr is not None, "the smoke benchmark scored zero benign rows"

    text = README.read_text(encoding="utf-8")
    # `[^.]*\.` was wrong here: it stops at the decimal point inside "75.2".
    match = re.search(
        r"bundled 50-row samples[^)]*\):.*?([0-9]+\.[0-9])% false-positive", text, re.S
    )
    assert match, "the README no longer states a smoke FPR in the expected shape"
    assert float(match.group(1)) == round(fpr * 100, 1), (
        f"README claims {match.group(1)}% smoke FPR, the tool reports {round(fpr * 100, 1)}%"
    )
