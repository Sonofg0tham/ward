"""Shared fixtures."""

from __future__ import annotations

import pytest

from ward.core.rules import RulePack, load_rule_pack


@pytest.fixture(scope="session")
def rule_pack() -> RulePack:
    return load_rule_pack()
