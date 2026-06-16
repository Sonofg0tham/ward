"""Benchmark harness: run Ward against public adversarial corpora.

Public entry points:
- ``CORPORA``: tuple of bundled corpus descriptors.
- ``run_benchmark``: scan one or more corpora and return a structured report.
- ``render_markdown`` / ``render_json``: format the report for humans / CI.
"""

from .corpora import CORPORA, Corpus, CorpusFit
from .report import render_json, render_markdown
from .runner import BenchReport, CorpusResult, run_benchmark

__all__ = [
    "CORPORA",
    "BenchReport",
    "Corpus",
    "CorpusFit",
    "CorpusResult",
    "render_json",
    "render_markdown",
    "run_benchmark",
]
