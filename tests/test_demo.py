"""Attack-demo scenarios must always be caught by Ward."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from ward.cli import app
from ward.core.engine import build_input, scan_inputs
from ward.core.models import Verdict
from ward.demo import DEMOS

runner = CliRunner()


@pytest.mark.parametrize("demo", DEMOS, ids=lambda d: d.name)
def test_demo_scenario_is_caught(rule_pack, demo):
    inputs = [build_input(inp.surface, inp.text, location=demo.name) for inp in demo.inputs]
    report = scan_inputs(inputs, rule_pack, target=demo.name)
    assert report.verdict is not Verdict.PASS, (
        f"Demo {demo.name!r} produced no findings. The narrative depends on Ward catching it."
    )


def test_attack_demo_list_command():
    result = runner.invoke(app, ["attack-demo", "--list"])
    assert result.exit_code == 0
    for d in DEMOS:
        assert d.name in result.stdout


def test_attack_demo_unknown_scenario_fails_cleanly():
    result = runner.invoke(app, ["attack-demo", "--scenario", "no-such-scenario"])
    assert result.exit_code == 2
