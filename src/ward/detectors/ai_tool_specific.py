"""Detects probes that target specific AI coding tools (Claude, Cursor, Antigravity)."""

from __future__ import annotations

from .base import RuleBasedDetector


class AIToolSpecificDetector(RuleBasedDetector):
    name = "ai_tool_specific"
    category = "ai_tool_specific"
