"""Run all synthetic PR fixtures through the engine and assert verdicts."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ward.core.engine import build_input, scan_inputs
from ward.core.models import Verdict

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _collect_fixtures() -> list[Path]:
    return sorted(p for p in FIXTURES_DIR.glob("*.yaml"))


@pytest.mark.parametrize("fixture_path", _collect_fixtures(), ids=lambda p: p.stem)
def test_fixture_verdict(rule_pack, fixture_path: Path) -> None:
    data = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
    inputs = [
        build_input(item["surface"], item["text"], location=fixture_path.name)
        for item in data["inputs"]
    ]
    report = scan_inputs(inputs, rule_pack, target=fixture_path.name)

    expected_verdict = Verdict(data["expect_verdict"])
    assert report.verdict is expected_verdict, (
        f"{fixture_path.name}: expected verdict {expected_verdict.value}, "
        f"got {report.verdict.value}. Findings: {[f.rule_id for f in report.findings]}"
    )

    expected_rules: list[str] = data.get("expect_rule_ids") or []
    fired = {f.rule_id for f in report.findings}
    if expected_rules:
        assert any(r in fired for r in expected_rules), (
            f"{fixture_path.name}: expected at least one of {expected_rules}; "
            f"fired: {sorted(fired)}"
        )
    else:
        assert not fired, f"{fixture_path.name}: expected clean, but rules fired: {sorted(fired)}"
