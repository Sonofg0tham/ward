"""Detects fake tool-call structures planted in free text."""

from __future__ import annotations

from .base import RuleBasedDetector


class ToolCallInjectionDetector(RuleBasedDetector):
    name = "tool_call_injection"
    category = "tool_call_injection"
