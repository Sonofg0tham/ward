"""Detector base class and the rule-driven default implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core.models import Finding, ScanInput
from ..core.rules import Rule, RulePack

_EVIDENCE_BUDGET = 160


def truncate_evidence(text: str, span: tuple[int, int]) -> str:
    """Return a small window of text around the match for the finding."""
    start, end = span
    pad = max(0, (_EVIDENCE_BUDGET - (end - start)) // 2)
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    snippet = text[a:b].strip().replace("\n", " ")
    if a > 0:
        snippet = "…" + snippet
    if b < len(text):
        snippet = snippet + "…"
    return snippet


class Detector(ABC):
    """A single detector. Implementations should be stateless and cheap to
    construct so the CLI can build them per-run."""

    name: str
    category: str

    @abstractmethod
    def scan(self, source: ScanInput) -> list[Finding]:
        """Return findings for one piece of untrusted text."""


class RuleBasedDetector(Detector):
    """Default detector: walks rules of a single category against the input.

    Subclasses normally only need to set ``category`` and ``name``. Override
    :meth:`scan` for extra heuristics beyond regex matching.
    """

    #: Which form of text to match against by default. Override to ``"raw"``
    #: when a detector needs to see unnormalised characters (e.g. obfuscation).
    matches_against: str = "normalised"

    def __init__(self, rule_pack: RulePack) -> None:
        self._rules: tuple[Rule, ...] = rule_pack.by_category(self.category)

    def _texts_for(self, source: ScanInput) -> list[str]:
        texts = [source.raw] if self.matches_against == "raw" else [source.normalised]
        # Always also scan any decoded base64/hex payloads. This lets a regex
        # rule catch instructions hidden inside an obfuscated blob.
        texts.extend(source.decoded)
        return texts

    def scan(self, source: ScanInput) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            if not rule.applies_to(source.surface):
                continue
            for text in self._texts_for(source):
                for pattern in rule.patterns:
                    match = pattern.search(text)
                    if match is None:
                        continue
                    findings.append(
                        Finding(
                            rule_id=rule.id,
                            detector=self.name,
                            category=rule.category,
                            severity=rule.severity,
                            message=rule.description,
                            surface=source.surface,
                            location=source.location,
                            evidence=truncate_evidence(text, match.span()),
                            remediation=rule.remediation,
                            references=rule.references,
                        )
                    )
                    # One hit per rule per surface is enough.
                    break
        return findings
