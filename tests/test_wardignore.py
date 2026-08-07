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


# --- segment-aware glob semantics -------------------------------------------
# fnmatch translates `*` to `.*`, which crosses `/`, so every pattern used to
# be implicitly recursive. `.wardignore` is committed, so an attacker can read
# it: a pattern that silently suppressed a whole subtree while the docs called
# it "one level" is somewhere to hide a payload.


@pytest.mark.parametrize(
    ("relpath", "patterns", "expected"),
    [
        # `*` stays inside one segment
        ("docs/api.md", ("docs/*",), True),
        ("docs/internal/secret/evil.md", ("docs/*",), False),
        ("tests/fixtures/a.md", ("tests/fixtures/*",), True),
        ("tests/fixtures/deep/nested/evil.md", ("tests/fixtures/*",), False),
        # `**` crosses segments
        ("docs/internal/secret/evil.md", ("docs/**/*",), True),
        ("tests/fixtures/deep/nested/evil.md", ("tests/fixtures/**/*",), True),
        # `**/` means zero or more leading directories
        ("evil.md", ("**/*.md",), True),
        ("a/b/c/evil.md", ("**/*.md",), True),
        # a literal directory covers its subtree
        ("build/out/bundle.js", ("build",), True),
        ("docs/generated/a.md", ("docs/generated/",), True),
        # `?` is one character and does not cross a separator
        ("docs/a.md", ("docs/?.md",), True),
        ("docs/ab.md", ("docs/?.md",), False),
        ("a/b.md", ("?/b.md",), True),
        # character classes
        ("logs/a1.txt", ("logs/a[0-9].txt",), True),
        ("logs/ax.txt", ("logs/a[0-9].txt",), False),
        ("logs/ax.txt", ("logs/a[!0-9].txt",), True),
        # an unclosed bracket is treated literally, not as a class
        ("weird[name.md", ("weird[name.md",), True),
    ],
)
def test_glob_is_segment_aware(relpath: str, patterns: tuple[str, ...], expected: bool):
    assert is_ignored(relpath, patterns) is expected


def test_a_glob_pattern_does_not_get_the_subtree_fallback():
    """Only LITERAL directory names expand to a subtree.

    Otherwise `docs/*` would expand to `docs/*/**` and quietly become
    recursive again, which is the behaviour this module exists to prevent.
    """
    assert not is_ignored("docs/internal/deep/evil.md", ("docs/*",))
    assert not is_ignored("tests/sub/test_x.py", ("tests/test_*.py",))
