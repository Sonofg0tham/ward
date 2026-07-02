"""Deterministic, offline judge for tests and demos.

The MockJudge is NOT an LLM. It flags text containing semantic markers that
the regex tier tends to miss - role-play framing, "you are now" takeovers,
reverse-order tricks - so the tiered architecture can be exercised and
demonstrated without an API key. Its markers are deliberately multi-word to
keep it from firing on ordinary prose.
"""

from __future__ import annotations

from .base import Judge, JudgeVerdict

# Semantic phrases that regex rules under-catch but a human (or LLM) reads as
# injection intent. Multi-word to avoid benign collisions.
_MARKERS: tuple[tuple[str, str], ...] = (
    ("pretend you are", "role_manipulation"),
    ("pretend to be", "role_manipulation"),
    ("act as a", "role_manipulation"),
    ("act as an", "role_manipulation"),
    ("you are now", "role_manipulation"),
    ("roleplay as", "role_manipulation"),
    ("new persona", "role_manipulation"),
    ("in reverse order", "obfuscation"),
    ("printed backwards", "obfuscation"),
    ("developer mode", "jailbreak"),
    ("do anything now", "jailbreak"),
    ("ignore all", "instruction_override"),
    ("disregard all", "instruction_override"),
    ("your real task", "instruction_override"),
    ("without any restrictions", "jailbreak"),
    ("step out of character", "jailbreak"),
)


class MockJudge(Judge):
    """Offline keyword judge. Deterministic; no network."""

    name = "mock"

    def classify(self, text: str) -> JudgeVerdict:
        lowered = text.lower()
        for phrase, technique in _MARKERS:
            if phrase in lowered:
                return JudgeVerdict(
                    is_injection=True,
                    confidence=0.8,
                    technique=technique,
                    reasoning=f"matched semantic marker {phrase!r}",
                )
        return JudgeVerdict(
            is_injection=False,
            confidence=0.1,
            technique="none",
            reasoning="no semantic injection markers found",
        )
