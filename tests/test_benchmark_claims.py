"""The benchmark figures in the README must be the ones the tool reports.

The README claimed 55.5% full-corpus recall while `ward bench` reported
54.2%. Nobody had re-run it after a round of rule work, so the headline
number in a detection tool's README was wrong - and wrong in the flattering
direction, which is the version that matters.

Only the SMOKE figure can be pinned against a live run. It uses the 50-row
samples bundled in the wheel, so it is offline, deterministic and safe in CI.
The full-corpus numbers need a download of several thousand rows.

But the full-corpus figures still have to agree with EACH OTHER, and twice
now they have not. The CHANGELOG stated "579 of the 1,048 rows ... 18 more
rows" three lines under a table saying 54.4%, which works out at 570 and 9 -
the counts were left behind when the percentage was recounted, in the same
paragraph that asserts "Every figure here is counted, not carried forward or
inferred". That much is checkable without downloading anything: a percentage
and a row count describing one run must be consistent, and so must the same
percentage quoted in three files.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from ward.bench.runner import run_benchmark

ROOT = pathlib.Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
CHANGELOG = ROOT / "CHANGELOG.md"
SECURITY = ROOT / "SECURITY.md"


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


def _changelog_blocking_recall() -> float:
    """The full-corpus blocking figure from the [Unreleased] table."""
    text = CHANGELOG.read_text(encoding="utf-8")
    match = re.search(
        r"Full corpus, blocking \(`fail-on: high`\)[^|]*\|[^|]*\|\s*\*\*([0-9]+\.[0-9])%\*\*",
        text,
    )
    assert match, "the CHANGELOG no longer states a full-corpus blocking recall"
    return float(match.group(1))


def test_changelog_row_counts_agree_with_its_own_percentage() -> None:
    """A percentage and a row count describing the same run must match.

    This is the check that was missing when the table said 54.4% and the
    sentence below it said 579 of 1,048 - which is 55.2%, the figure the
    table used to carry. Overstating the detection gain by 2x is exactly the
    direction a benchmark claim should never drift in.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    caught = re.search(r"([0-9,]+) of the\s+([0-9,]+) in-scope injection rows", text)
    assert caught, "the CHANGELOG no longer states the caught/total row counts"
    detected = int(caught.group(1).replace(",", ""))
    total = int(caught.group(2).replace(",", ""))

    claimed = _changelog_blocking_recall()
    counted = round(detected / total * 100, 1)
    assert counted == claimed, (
        f"CHANGELOG says {detected} of {total} rows ({counted}%) but its own table "
        f"says {claimed}%. Re-run `ward bench` and update both together."
    )

    # The prose is hard-wrapped, so every gap here has to be \s+ rather than a
    # literal space - a strictness that has already cost this file one false
    # "the CHANGELOG no longer states..." failure.
    baseline = re.search(
        r"against\s+([0-9,]+)\s+at\s+v[0-9.]+,\s+so\s+\*\*([0-9,]+)\s+more\s+rows\*\*", text
    )
    assert baseline, "the CHANGELOG no longer states the baseline row delta"
    prior = int(baseline.group(1).replace(",", ""))
    delta = int(baseline.group(2).replace(",", ""))
    assert detected - prior == delta, (
        f"CHANGELOG says {delta} more rows, but {detected} - {prior} = {detected - prior}"
    )


def test_the_full_corpus_figure_is_the_same_in_every_file() -> None:
    """README, SECURITY and CHANGELOG quote one number for one run.

    Three files carrying a benchmark headline is three places to forget, and
    the README has already shipped a figure no run reproduced.
    """
    claimed = _changelog_blocking_recall()

    readme = re.search(
        r"Full corpus[^)]*\)[^*]*\*\*([0-9]+\.[0-9])%\s*\n?\s*in-scope recall",
        README.read_text(encoding="utf-8"),
    )
    assert readme, "the README no longer states a full-corpus recall in the expected shape"
    assert float(readme.group(1)) == claimed, (
        f"README says {readme.group(1)}% full-corpus recall, CHANGELOG says {claimed}%"
    )

    security = re.search(
        r"\|\s*`high` \(default\)\s*\|\s*([0-9]+\.[0-9])%\s*\|",
        SECURITY.read_text(encoding="utf-8"),
    )
    assert security, "SECURITY.md no longer states the blocking-threshold recall"
    assert float(security.group(1)) == claimed, (
        f"SECURITY.md says {security.group(1)}% at fail-on high, CHANGELOG says {claimed}%"
    )
