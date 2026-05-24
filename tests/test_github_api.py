"""Tests for github_api parsing helpers. Network paths are exercised by the
CLI integration tests against a fake server in v0.2; for v0.1 we cover the
pure-function bits only."""

from __future__ import annotations

import pytest

from ward.core.github_api import parse_pr_ref


def test_parse_pr_ref_happy_path():
    assert parse_pr_ref("sonofg0tham/ward#42") == ("sonofg0tham", "ward", 42)


@pytest.mark.parametrize(
    "ref",
    [
        "missing-hash",
        "no/repo",
        "owner/repo#not-a-number",
        "#42",
        "owner#42",
    ],
)
def test_parse_pr_ref_rejects_bad_input(ref: str):
    with pytest.raises(ValueError):
        parse_pr_ref(ref)
