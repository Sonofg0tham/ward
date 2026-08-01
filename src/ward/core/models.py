"""Shared data models used across detectors, reporters, and the CLI."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class Severity(str, Enum):
    """Severity ladder. Order matters for threshold comparisons."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @staticmethod
    def _rank_of(other: object) -> int | None:
        """The rank to compare against, or None if there is no sane answer.

        Severity subclasses str so that str(Severity.HIGH) is "high", which
        the reporters rely on. The cost is that returning NotImplemented from
        a comparison does not raise - Python falls back to str.__ge__ and
        compares ALPHABETICALLY. `Severity.CRITICAL >= "high"` was False and
        `Severity.LOW >= "high"` was True, silently, for any SDK caller who
        wrote a threshold as a string. So a string that names a severity is
        coerced, and anything else raises rather than quietly ranking "critical"
        below "high" because c sorts before h.
        """
        if isinstance(other, Severity):
            return other.rank
        if isinstance(other, str):
            try:
                return Severity(other.lower()).rank
            except ValueError:
                return None
        return None

    def __ge__(self, other: object) -> bool:
        rank = self._rank_of(other)
        if rank is None:
            raise TypeError(f"cannot compare Severity with {other!r}")
        return self.rank >= rank

    def __gt__(self, other: object) -> bool:
        rank = self._rank_of(other)
        if rank is None:
            raise TypeError(f"cannot compare Severity with {other!r}")
        return self.rank > rank

    def __le__(self, other: object) -> bool:
        rank = self._rank_of(other)
        if rank is None:
            raise TypeError(f"cannot compare Severity with {other!r}")
        return self.rank <= rank

    def __lt__(self, other: object) -> bool:
        rank = self._rank_of(other)
        if rank is None:
            raise TypeError(f"cannot compare Severity with {other!r}")
        return self.rank < rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


Surface = Literal[
    "branch_name",
    "tag_name",
    "commit_message",
    "commit_author",
    "file_name",
    "directory_name",
    "file_content",
    "code_comment",
    "pr_title",
    "pr_body",
    "issue_title",
    "issue_body",
    "stdin",
]


@dataclass(frozen=True)
class ScanInput:
    """A single piece of untrusted text to be scanned.

    ``raw`` is the bytes-as-received text.
    ``normalised`` is the NFKC-normalised, zero-width-stripped form used by
    most detectors. Detectors that specifically look for obfuscation should
    use ``raw`` directly.
    ``decoded`` carries any base64 / hex blocks that were unwrapped during
    normalisation, so other detectors can scan the decoded content too.
    ``suppressed_rules`` carries rule-id globs (e.g. ``io.*``) extracted from
    inline ``<!-- ward-allow-file: ... -->`` directives. Findings whose
    rule id matches any glob are dropped before aggregation. This is the
    documented escape hatch for files that legitimately discuss prompt
    injection (security research, Ward's own docs, etc).
    ``demoted_rules`` carries rule-id globs whose findings are reported at
    MEDIUM instead of their own severity. Suppression and demotion answer two
    different questions: suppression is for a finding that is an ARTEFACT (a
    U+202E manufactured by re-reading ASCII as UTF-16 is not in the document
    at all), demotion is for a finding that is real but arrived through a
    reading Ward had to reconstruct. Demoting rather than suppressing is what
    stops a whole-file judgement about the bytes from being able to silence a
    detector - see ``_Readings`` in cli.py.
    """

    surface: Surface
    raw: str
    normalised: str
    decoded: tuple[str, ...] = field(default_factory=tuple)
    location: str = ""  # e.g. "README.md:12" or "commit abc1234"
    suppressed_rules: frozenset[str] = field(default_factory=frozenset)
    demoted_rules: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Finding:
    """A single rule hit."""

    rule_id: str
    detector: str
    category: str
    severity: Severity
    message: str
    surface: Surface
    location: str
    evidence: str
    remediation: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)


class Verdict(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class ScanReport:
    """Aggregated outcome of a scan run."""

    findings: tuple[Finding, ...]
    verdict: Verdict
    fail_on: Severity
    threshold: Severity
    target: str

    @property
    def exit_code(self) -> int:
        return {Verdict.PASS: 0, Verdict.WARN: 1, Verdict.FAIL: 2}[self.verdict]

    def filtered(self) -> Sequence[Finding]:
        return [f for f in self.findings if f.severity >= self.threshold]
