"""Run Ward against a corpus and compute detection metrics."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..core.engine import build_input, scan_inputs
from ..core.models import Severity, Surface, Verdict
from ..core.rules import RulePack, load_rule_pack
from .corpora import CORPORA, Corpus, CorpusFit, load_rows


@dataclass(frozen=True)
class CorpusResult:
    """Result of scanning one corpus."""

    corpus: Corpus
    total: int
    expected_positive: int
    expected_negative: int
    detected_positive: int
    detected_negative: int  # false positives (benign rows that triggered)
    missed_positive: int  # false negatives (injection rows that did not trigger)
    fired_categories: dict[str, int] = field(default_factory=dict)

    @property
    def recall(self) -> float:
        return (self.detected_positive / self.expected_positive) if self.expected_positive else 0.0

    @property
    def false_positive_rate(self) -> float:
        return (self.detected_negative / self.expected_negative) if self.expected_negative else 0.0

    @property
    def precision(self) -> float:
        positives_flagged = self.detected_positive + self.detected_negative
        if not positives_flagged:
            return 0.0
        return self.detected_positive / positives_flagged


@dataclass(frozen=True)
class BenchReport:
    """Aggregated benchmark report across multiple corpora."""

    results: tuple[CorpusResult, ...]
    fail_on: Severity
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    ward_version: str = ""

    @property
    def overall_recall(self) -> float:
        in_scope = [r for r in self.results if r.corpus.fit is CorpusFit.IN_SCOPE]
        pos = sum(r.expected_positive for r in in_scope)
        det = sum(r.detected_positive for r in in_scope)
        return (det / pos) if pos else 0.0

    @property
    def overall_false_positive_rate(self) -> float:
        in_scope = [r for r in self.results if r.corpus.fit is CorpusFit.IN_SCOPE]
        neg = sum(r.expected_negative for r in in_scope)
        fp = sum(r.detected_negative for r in in_scope)
        return (fp / neg) if neg else 0.0


def _surface_for(corpus: Corpus) -> Surface:
    return corpus.surface  # type: ignore[return-value]


def _scan_one(
    text: str, surface: Surface, pack: RulePack, fail_on: Severity
) -> tuple[bool, list[str]]:
    """Scan a single row and return (detected, fired_rule_ids)."""
    inputs = [build_input(surface, text, location="bench")]
    report = scan_inputs(inputs, pack, target="bench", fail_on=fail_on)
    detected = report.verdict is Verdict.FAIL
    return detected, [f.rule_id for f in report.findings]


def run_benchmark(
    corpora: Iterable[Corpus] = CORPORA,
    *,
    rule_pack: RulePack | None = None,
    fail_on: Severity = Severity.HIGH,
) -> BenchReport:
    """Scan each corpus and return the aggregated report."""
    from .. import __version__

    pack = rule_pack or load_rule_pack()
    results: list[CorpusResult] = []
    for corpus in corpora:
        rows = load_rows(corpus)
        surface = _surface_for(corpus)
        expected_positive = sum(1 for _, ep in rows if ep)
        expected_negative = sum(1 for _, ep in rows if not ep)
        detected_positive = 0
        detected_negative = 0
        missed_positive = 0
        fired_categories: dict[str, int] = {}
        for text, expect in rows:
            detected, rule_ids = _scan_one(text, surface, pack, fail_on)
            if detected and expect:
                detected_positive += 1
            elif detected and not expect:
                detected_negative += 1
            elif not detected and expect:
                missed_positive += 1
            for rid in rule_ids:
                # Category is the slug before the first dot.
                cat = rid.split(".", 1)[0]
                fired_categories[cat] = fired_categories.get(cat, 0) + 1
        results.append(
            CorpusResult(
                corpus=corpus,
                total=len(rows),
                expected_positive=expected_positive,
                expected_negative=expected_negative,
                detected_positive=detected_positive,
                detected_negative=detected_negative,
                missed_positive=missed_positive,
                fired_categories=fired_categories,
            )
        )
    return BenchReport(
        results=tuple(results),
        fail_on=fail_on,
        ward_version=__version__,
    )
