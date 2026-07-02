"""Anthropic-backed judge.

Uses the Claude API to classify whether a short untrusted string is a
prompt-injection attempt. Design choices, per Ward's constraints and the
Anthropic SDK guidance:

- **Model default: claude-haiku-4-5.** This is a high-volume binary
  classifier where cost and latency dominate, so the cheap/fast tier is the
  right default (overridable). Ward runs it only on inputs the regex tier
  could not decide.
- **Prompt caching** on the system prompt (``cache_control: ephemeral``). The
  system prompt is stable across calls; the volatile untrusted text lives in
  the user turn after it. (On Haiku the cacheable-prefix minimum is ~4096
  tokens - a short classifier prompt may not meet it, in which case caching is
  a no-op with no correctness impact.)
- **Structured output** (``output_config.format``) forces a JSON verdict, so
  adversarial input cannot steer the model into free-text obedience.
- **Lazy import + injectable client** so ``ward`` core never hard-depends on
  ``anthropic`` and the classify path is unit-testable without a network call.
"""

from __future__ import annotations

import os
from typing import Any

from .base import Judge, JudgeError, JudgeVerdict
from .prompt import SYSTEM_PROMPT, VERDICT_SCHEMA, build_user_content, parse_verdict

DEFAULT_MODEL = "claude-haiku-4-5"


class AnthropicJudge(Judge):
    """Judge backed by the Claude API.

    ``client`` may be injected for testing; otherwise a real
    ``anthropic.Anthropic()`` is constructed lazily on first use.
    """

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, *, client: Any | None = None) -> None:
        self.model = model
        self._client = client

    def available(self) -> bool:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        # Pragmatic readiness gate: an explicit key/token in the environment.
        # (Profile-based auth via `ant auth login` is not detected here - set
        # ANTHROPIC_API_KEY to enable the judge in that case.)
        return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError as exc:
            raise JudgeError(
                "The anthropic package is required for the LLM judge. Install it with:\n"
                '    pip install "ward-scanner[judge]"'
            ) from exc
        self._client = anthropic.Anthropic()
        return self._client

    def classify(self, text: str) -> JudgeVerdict:
        client = self._get_client()
        try:
            response = client.messages.create(
                model=self.model,
                max_tokens=256,
                system=[
                    {
                        "type": "text",
                        "text": SYSTEM_PROMPT,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                output_config={"format": {"type": "json_schema", "schema": VERDICT_SCHEMA}},
                messages=[{"role": "user", "content": build_user_content(text)}],
            )
        except Exception as exc:  # surface any SDK/transport error uniformly
            raise JudgeError(f"judge request failed: {exc}") from exc

        raw = _first_text_block(response)
        if not raw:
            raise JudgeError("judge returned no text content")
        try:
            return parse_verdict(raw)
        except (ValueError, TypeError) as exc:
            raise JudgeError(f"could not parse judge response: {exc}") from exc


def _first_text_block(response: Any) -> str:
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text":
            return str(getattr(block, "text", ""))
    return ""
