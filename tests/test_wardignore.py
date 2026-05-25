"""Tests for the .wardignore loader / matcher."""

from __future__ import annotations

from pathlib import Path

import pytest

from ward.core.wardignore import is_ignored, load_patterns


def test_load_patterns_missing_file(tmp_path: Path):
    assert load_patterns(tmp_path) == ()


def test_load_patterns_skips_comments_and_blanks(tmp_path: Path):
    (tmp_path / ".wardignore").write_text(
        "# A comment\nsrc/ward/*\n\ntests/fixtures/**  # trailing comment\n",
        encoding="utf-8",
    )
    patterns = load_patterns(tmp_path)
    assert patterns == ("src/ward/*", "tests/fixtures/**")


@pytest.mark.parametrize(
    "relpath,expected",
    [
        ("src/ward/cli.py", True),
        ("src/ward/core/normalise.py", True),
        ("docs/index.md", False),
        ("tests/fixtures/01_x.yaml", True),
        ("tests/test_detectors.py", True),
        ("tests/test_lab.py", True),
        ("README.md", False),
        ("action/action.yml", True),
    ],
)
def test_is_ignored_matches_expected_paths(relpath: str, expected: bool):
    patterns = (
        "src/ward/*",
        "src/ward/**/*",
        "tests/fixtures/*",
        "tests/fixtures/**/*",
        "tests/test_*.py",
        "action/*",
    )
    assert is_ignored(relpath, patterns) is expected


def test_is_ignored_handles_windows_separators():
    patterns = ("src/ward/**/*",)
    assert is_ignored("src\\ward\\core\\normalise.py", patterns)


def test_is_ignored_no_patterns_means_nothing_ignored():
    assert not is_ignored("any/path/at/all.py", ())
