"""Run Ward against a corpus and compute detection metrics."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..core.engine import build_input, scan_inputs
from ..core.models import Severity, Surface, Verdict
from ..core.rules import RulePack, load_rule_pack
from ..judge import Judge
from .corpora import CORPORA, Corpus, CorpusFit, load_rows


@dataclass(frozen=True)
class CorpusResult:
    """Result of scanning one corpus.

    The base fields describe the regex (tier-1) result. The ``judge_*`` fields
    are populated only when a judge ran; they describe its *marginal*
    contribution over regex - rows regex missed that the judge recovered, and
    benign rows regex passed that the judge wrongly flagged.
    """

    corpus: Corpus
    total: int
    expected_positive: int
    expected_negative: int
    detected_positive: int
    detected_negative: int  # false positives (benign rows that triggered)
    missed_positive: int  # false negatives (injection rows that did not trigger)
    fired_categories: dict[str, int] = field(default_factory=dict)
    judge_ran: bool = False
    judge_recovered_positive: int = 0  # expected-positive rows regex missed, judge caught
    judge_false_positive: int = 0  # expected-negative rows regex passed, judge flagged
    judge_errors: int = 0

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

    @property
    def combined_recall(self) -> float:
        """Recall of regex + judge together."""
        if not self.expected_positive:
            return 0.0
        return (self.detected_positive + self.judge_recovered_positive) / self.expected_positive

    @property
    def combined_false_positive_rate(self) -> float:
        if not self.expected_negative:
            return 0.0
        return (self.detected_negative + self.judge_false_positive) / self.expected_negative


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

    @property
    def judge_ran(self) -> bool:
        return any(r.judge_ran for r in self.results)

    @property
    def overall_combined_recall(self) -> float:
        in_scope = [r for r in self.results if r.corpus.fit is CorpusFit.IN_SCOPE]
        pos = sum(r.expected_positive for r in in_scope)
        det = sum(r.detected_positive + r.judge_recovered_positive for r in in_scope)
        return (det / pos) if pos else 0.0

    @property
    def overall_combined_false_positive_rate(self) -> float:
        in_scope = [r for r in self.results if r.corpus.fit is CorpusFit.IN_SCOPE]
        neg = sum(r.expected_negative for r in in_scope)
        fp = sum(r.detected_negative + r.judge_false_positive for r in in_scope)
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
    judge: Judge | None = None,
    judge_threshold: float = 0.5,
) -> BenchReport:
    """Scan each corpus and return the aggregated report.

    When ``judge`` is supplied, every row the regex tier did NOT flag is passed
    to the judge; a verdict of injection at or above ``judge_threshold`` counts
    as a recovery (on an expected-positive row) or a new false positive (on an
    expected-negative row). The judge is never asked about rows regex already
    caught, so its cost scales with the miss set, not the whole corpus.
    """
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
        judge_recovered_positive = 0
        judge_false_positive = 0
        judge_errors = 0
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

            # Judge tier runs only on rows regex did not already flag.
            if judge is not None and not detected:
                judged = _judge_one(judge, text, judge_threshold)
                if judged is None:
                    judge_errors += 1
                elif judged:
                    if expect:
                        judge_recovered_positive += 1
                    else:
                        judge_false_positive += 1

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
                judge_ran=judge is not None,
                judge_recovered_positive=judge_recovered_positive,
                judge_false_positive=judge_false_positive,
                judge_errors=judge_errors,
            )
        )
    return BenchReport(
        results=tuple(results),
        fail_on=fail_on,
        ward_version=__version__,
    )


def _judge_one(judge: Judge, text: str, threshold: float) -> bool | None:
    """Return True/False for the judge verdict, or None if the judge errored."""
    from ..judge import JudgeError

    try:
        verdict = judge.classify(text)
    except JudgeError:
        return None
    return verdict.is_injection and verdict.confidence >= threshold
