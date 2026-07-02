"""Judge abstraction: the optional LLM second tier.

Ward's tier 1 is the regex engine (fast, offline, deterministic). The judge
is an OPTIONAL tier 2 that classifies text the regex tier could not decide,
catching semantic injections (paraphrases, role-play, novel phrasings) that
regex structurally misses. It is off by default and degrades gracefully when
no model backend is configured.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

# The technique labels a judge may return. Kept small and stable so the schema
# is cache-friendly and callers can switch on it.
TECHNIQUES: tuple[str, ...] = (
    "instruction_override",
    "role_manipulation",
    "exfiltration",
    "obfuscation",
    "tool_call_injection",
    "jailbreak",
    "none",
)


@dataclass(frozen=True)
class JudgeVerdict:
    """A single classification result."""

    is_injection: bool
    confidence: float  # 0.0 - 1.0, clamped by the judge
    technique: str  # one of TECHNIQUES
    reasoning: str


class Judge(ABC):
    """Base class for judges. Implementations must be safe to construct even
    when their backend is unavailable; ``available()`` reports readiness."""

    name: str

    @abstractmethod
    def classify(self, text: str) -> JudgeVerdict:
        """Classify one untrusted string. May raise on backend failure."""

    def available(self) -> bool:
        """Whether this judge can actually run (deps + credentials present)."""
        return True


class JudgeError(RuntimeError):
    """Raised when a judge backend fails irrecoverably for one input."""
