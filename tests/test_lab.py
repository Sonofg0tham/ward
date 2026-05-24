"""Lab harness tests."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ward.cli import app
from ward.core.models import Verdict
from ward.demo import DEMOS
from ward.lab import MockReviewerAgent, render_markdown, run_default_lab, run_lab


def test_mock_agent_review_includes_input(rule_pack):
    from ward.core.engine import build_input

    inp = build_input("pr_body", "Hello world", location="t")
    agent = MockReviewerAgent()
    transcript = agent.review((inp,))
    assert "Hello world" in transcript
    assert "pr_body" in transcript


def test_run_default_lab_catches_all(rule_pack):
    report = run_default_lab(rule_pack)
    assert report.total == len(DEMOS)
    assert report.caught == report.total, (
        "Every bundled demo scenario must be blocked by Ward; the lab "
        "narrative depends on it."
    )


def test_run_lab_protected_pipeline_blocks(rule_pack):
    report = run_lab(DEMOS[:1], rule_pack)
    run = report.runs[0]
    assert run.blocked_by_ward
    assert run.ward_verdict is Verdict.FAIL
    assert "rejected by Ward" in run.protected_transcript


def test_markdown_report_is_self_contained(rule_pack):
    report = run_default_lab(rule_pack)
    md = render_markdown(report)
    assert md.startswith("# Ward lab report")
    assert "## Method" in md
    assert "## Scenario 1:" in md
    assert "## Conclusion" in md
    # Every demo should be mentioned by title.
    for d in DEMOS:
        assert d.title in md


def test_cli_lab_attack_writes_report(tmp_path, rule_pack):
    runner = CliRunner()
    target = tmp_path / "report.md"
    result = runner.invoke(app, ["lab", "attack", "--output", str(target)])
    assert result.exit_code == 0
    assert target.exists()
    body = target.read_text(encoding="utf-8")
    assert "# Ward lab report" in body
    assert "5/5" in result.stdout or "Blocked by Ward:" in result.stdout


def test_cli_lab_attack_no_write_prints_to_stdout(rule_pack):
    runner = CliRunner()
    result = runner.invoke(app, ["lab", "attack", "--no-write"])
    assert result.exit_code == 0
    assert "# Ward lab report" in result.stdout
