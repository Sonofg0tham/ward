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
