"""Tests for the benchmark harness."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from ward.bench import CORPORA, render_json, render_markdown, run_benchmark
from ward.bench.corpora import CorpusFit, load_rows
from ward.cli import app

runner = CliRunner()


def test_corpora_have_sample_files():
    for corpus in CORPORA:
        rows = load_rows(corpus)
        assert rows, f"{corpus.name} returned no rows from bundled sample"


def test_run_benchmark_produces_one_result_per_corpus():
    report = run_benchmark()
    assert len(report.results) == len(CORPORA)
    for result in report.results:
        assert result.total > 0


def test_in_scope_corpora_score_non_zero():
    """Smoke test: every in-scope corpus must catch at least one row.
    A regression to 0% on Lakera or Spikee would be a real bug."""
    report = run_benchmark()
    for r in report.results:
        if r.corpus.fit is CorpusFit.IN_SCOPE and r.expected_positive > 0:
            assert r.detected_positive > 0, (
                f"{r.corpus.name}: zero in-scope detections is a regression"
            )


def test_false_positive_rate_stays_low():
    """deepset has labelled benign rows. FPR should remain at or near zero;
    treat any creep above 10% as a regression."""
    report = run_benchmark()
    for r in report.results:
        if r.expected_negative > 0:
            assert r.false_positive_rate <= 0.10, (
                f"{r.corpus.name}: FPR {r.false_positive_rate:.1%} exceeds 10% ceiling"
            )


def test_ceiling_corpus_is_labelled():
    advbench = next(c for c in CORPORA if c.name == "advbench_harmful_behaviors")
    assert advbench.fit is CorpusFit.CEILING_TEST


def test_render_markdown_includes_headline_numbers():
    report = run_benchmark()
    md = render_markdown(report)
    assert "# Ward benchmark report" in md
    assert "In-scope recall" in md
    assert "Per-corpus results" in md
    assert "Honest caveats" in md
    for corpus in CORPORA:
        assert corpus.name in md


def test_render_json_is_valid_and_has_summary():
    report = run_benchmark()
    payload = json.loads(render_json(report))
    assert payload["tool"] == "ward"
    assert "summary" in payload
    assert "corpora" in payload
    assert len(payload["corpora"]) == len(CORPORA)


def test_cli_bench_list():
    result = runner.invoke(app, ["bench", "--list"])
    assert result.exit_code == 0
    for corpus in CORPORA:
        assert corpus.name in result.stdout


def test_cli_bench_unknown_corpus_fails_cleanly():
    result = runner.invoke(app, ["bench", "--corpus", "no_such_corpus"])
    assert result.exit_code == 2


def test_cli_bench_no_write_emits_markdown_to_stdout():
    result = runner.invoke(app, ["bench", "--no-write"])
    assert result.exit_code == 0
    assert "# Ward benchmark report" in result.stdout


def test_cli_bench_json_format():
    result = runner.invoke(app, ["bench", "--no-write", "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert "summary" in payload


def _sample_report(recall: float, fpr: float, per_corpus: dict[str, float]) -> dict:
    return {
        "version": "0.1.x",
        "summary": {
            "overall_recall_in_scope": recall,
            "overall_false_positive_rate_in_scope": fpr,
        },
        "corpora": [
            {"name": name, "recall": rec, "fit": "in_scope"} for name, rec in per_corpus.items()
        ],
    }


def test_render_diff_flags_improvement():
    from ward.bench.compare import render_diff

    base = _sample_report(0.60, 0.0, {"lakera": 0.32})
    new = _sample_report(0.75, 0.0, {"lakera": 0.68})
    body = render_diff(base, new)
    assert "In-scope recall" in body
    assert "+15.0pp" in body or "+15.1pp" in body
    assert "✅" in body


def test_render_diff_flags_regression():
    from ward.bench.compare import render_diff

    base = _sample_report(0.80, 0.02, {"lakera": 0.70})
    new = _sample_report(0.60, 0.02, {"lakera": 0.40})
    body = render_diff(base, new)
    assert "Recall regression" in body
    assert "⚠️" in body


def test_render_diff_flags_fpr_regression():
    from ward.bench.compare import render_diff

    base = _sample_report(0.70, 0.0, {"lakera": 0.68})
    new = _sample_report(0.70, 0.15, {"lakera": 0.68})
    body = render_diff(base, new)
    assert "False-positive regression" in body


def test_render_diff_no_change():
    from ward.bench.compare import render_diff

    r = _sample_report(0.75, 0.0, {"lakera": 0.68})
    body = render_diff(r, r)
    assert "No change to headline" in body


def test_cli_bench_diff_command(tmp_path):
    base_path = tmp_path / "base.json"
    new_path = tmp_path / "new.json"
    base_path.write_text(json.dumps(_sample_report(0.60, 0.0, {"lakera": 0.32})), encoding="utf-8")
    new_path.write_text(json.dumps(_sample_report(0.75, 0.0, {"lakera": 0.68})), encoding="utf-8")
    result = runner.invoke(app, ["bench-diff", str(base_path), str(new_path)])
    assert result.exit_code == 0
    assert "Ward bench diff" in result.stdout


# --- judge tier integration -------------------------------------------------


def test_bench_without_judge_leaves_judge_fields_default():
    report = run_benchmark()
    assert not report.judge_ran
    for r in report.results:
        assert r.judge_ran is False
        assert r.judge_recovered_positive == 0


def test_bench_with_mock_judge_shows_lift_and_no_new_fp():
    from ward.judge import MockJudge

    report = run_benchmark(judge=MockJudge())
    assert report.judge_ran
    # The mock recovers at least one semantic row regex misses...
    assert sum(r.judge_recovered_positive for r in report.results) > 0
    # ...and combined recall is at least the regex recall.
    assert report.overall_combined_recall >= report.overall_recall
    # ...without introducing benign false positives on the labelled corpus.
    assert report.overall_combined_false_positive_rate <= report.overall_false_positive_rate + 1e-9


def test_bench_report_markdown_has_judge_section_when_judge_ran():
    from ward.judge import MockJudge

    report = run_benchmark(judge=MockJudge())
    md = render_markdown(report)
    assert "Judge tier" in md
    assert "regex + judge" in md


def test_bench_report_json_carries_judge_fields():
    from ward.judge import MockJudge

    report = run_benchmark(judge=MockJudge())
    payload = json.loads(render_json(report))
    assert payload["summary"]["judge_ran"] is True
    assert "overall_combined_recall_in_scope" in payload["summary"]
    assert all("judge_recovered_positive" in c for c in payload["corpora"])


def test_bench_judge_survives_erroring_judge():
    """A judge that raises JudgeError on every row must not crash the run;
    the errors are counted and reported."""
    from ward.judge import Judge, JudgeError

    class _BoomJudge(Judge):
        name = "boom"

        def classify(self, text: str):
            raise JudgeError("always fails")

    report = run_benchmark(judge=_BoomJudge())
    assert report.judge_ran
    assert sum(r.judge_errors for r in report.results) > 0
    # No recoveries, no new FPs, recall unchanged.
    assert report.overall_combined_recall == report.overall_recall


def test_cli_bench_with_mock_judge():
    result = runner.invoke(app, ["bench", "--no-write", "--judge", "mock"])
    assert result.exit_code == 0
    assert "regex + judge" in result.stdout


def test_cli_bench_judge_unknown_engine_errors():
    result = runner.invoke(app, ["bench", "--no-write", "--judge", "no-such"])
    assert result.exit_code == 2
