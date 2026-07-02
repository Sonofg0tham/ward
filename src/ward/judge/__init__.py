"""Optional LLM-judge tier.

Tier 1 (regex) always runs. The judge is an opt-in tier 2 for the ambiguous
and semantic cases regex misses. Off by default; degrades gracefully with no
backend configured.

    from ward.judge import get_judge
    judge = get_judge("anthropic")   # or "mock"
    if judge.available():
        verdict = judge.classify(untrusted_text)
"""

from __future__ import annotations

from .anthropic_judge import AnthropicJudge
from .base import TECHNIQUES, Judge, JudgeError, JudgeVerdict
from .mock import MockJudge

JUDGE_ENGINES: tuple[str, ...] = ("mock", "anthropic")


def get_judge(name: str, *, model: str | None = None) -> Judge:
    """Construct a judge by engine name. Raises ValueError on unknown name."""
    if name == "mock":
        return MockJudge()
    if name == "anthropic":
        return AnthropicJudge(model=model) if model else AnthropicJudge()
    raise ValueError(f"unknown judge engine: {name!r} (choose from {', '.join(JUDGE_ENGINES)})")


__all__ = [
    "JUDGE_ENGINES",
    "TECHNIQUES",
    "AnthropicJudge",
    "Judge",
    "JudgeError",
    "JudgeVerdict",
    "MockJudge",
    "get_judge",
]
