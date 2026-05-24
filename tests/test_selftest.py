"""Selftest scenarios must always be detected by the engine."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from ward.cli import app
from ward.core.engine import build_input, scan_inputs
from ward.selftest import SCENARIOS

runner = CliRunner()


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_selftest_scenario_fires_expected_rule(rule_pack, scenario):
    inputs = [build_input(scenario.surface, scenario.payload, location=scenario.name)]
    report = scan_inputs(inputs, rule_pack, target=scenario.name)
    fired = {f.rule_id for f in report.findings}
    assert scenario.expect_rule in fired, (
        f"{scenario.name}: expected {scenario.expect_rule}; fired {sorted(fired)}"
    )


def test_selftest_command_exits_clean():
    result = runner.invoke(app, ["selftest"])
    assert result.exit_code == 0
    assert "Overall" in result.stdout
    assert "all scenarios detected" in result.stdout
