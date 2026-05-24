"""False-positive guardrail.

Every fixture in tests/fixtures/clean/ must scan to a PASS verdict. If one
starts failing, either the fixture was secretly adversarial (move it) or a
rule got too greedy (tighten it).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from ward.core.engine import build_input, scan_inputs
from ward.core.models import Verdict

CLEAN_DIR = Path(__file__).parent / "fixtures" / "clean"


def _collect_clean_fixtures() -> list[Path]:
    return sorted(p for p in CLEAN_DIR.glob("*.yaml"))


@pytest.mark.parametrize("fixture_path", _collect_clean_fixtures(), ids=lambda p: p.stem)
def test_clean_fixture_passes(rule_pack, fixture_path: Path) -> None:
    data = yaml.safe_load(fixture_path.read_text(encoding="utf-8"))
    inputs = [
        build_input(item["surface"], item["text"], location=fixture_path.name)
        for item in data["inputs"]
    ]
    report = scan_inputs(inputs, rule_pack, target=fixture_path.name)
    assert report.verdict is Verdict.PASS, (
        f"{fixture_path.name}: expected PASS but got {report.verdict.value}. "
        f"Findings: {[(f.rule_id, f.evidence[:80]) for f in report.findings]}"
    )
