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

# The first anthropic release whose Messages.create accepts output_config.
# Verified by inspecting the create() signature in each published wheel;
# 0.76 does not have it. Quoted in the upgrade hint, not used as the check.
MIN_SDK_HINT = "0.77"


def _supports_structured_outputs() -> bool:
    """Does the installed SDK accept ``output_config`` on ``messages.create``?

    A capability probe rather than a version comparison. ``Messages.create``
    is generated with keyword-only parameters and no ``**kwargs``, so passing
    ``output_config`` to an older SDK raises TypeError before any request is
    made. Inspecting the signature answers the question directly and stays
    correct if the parameter is ever backported or renamed upstream.
    """
    try:
        import inspect

        from anthropic.resources.messages import Messages

        signature = inspect.signature(Messages.create)
    except Exception:  # ImportError, or a restructured SDK we cannot introspect
        # Unknown rather than absent. Say yes and let the real call fail with
        # the SDK's own error, which beats refusing to run against a working
        # SDK we simply could not introspect.
        return True
    return "output_config" in signature.parameters


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
        return self.unavailable_reason() is None

    def unavailable_reason(self) -> str | None:
        """Why the judge cannot run, or None if it can.

        Checking that ``import anthropic`` succeeds is not enough. The SDK's
        ``Messages.create`` is generated with keyword-only parameters and no
        ``**kwargs``, so an older release does not merely ignore
        ``output_config`` - it raises TypeError, which surfaced as an
        unreadable "unexpected keyword argument" for anyone whose environment
        already had a 0.4x-0.7x installed. ``available()`` reported ready
        because it only looked for the import and a key.

        Testing the capability rather than the version number keeps this
        correct if the SDK ever renames or backports the parameter.
        """
        try:
            import anthropic
        except ImportError:
            return (
                "the anthropic SDK is not installed. Install Ward's judge "
                "extra: pip install 'ward-scanner[judge]'"
            )
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            # Profile-based auth via `ant auth login` is not detected here.
            return "no ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN in the environment"
        if not _supports_structured_outputs():
            version = getattr(anthropic, "__version__", "unknown")
            return (
                f"the installed anthropic SDK ({version}) is too old for structured "
                "outputs, which Ward's judge requires. Upgrade it: "
                f"pip install -U 'anthropic>={MIN_SDK_HINT}'"
            )
        return None

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
