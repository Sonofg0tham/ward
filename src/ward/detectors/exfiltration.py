"""Detects instructions that try to make the agent leak data."""

from __future__ import annotations

from .base import RuleBasedDetector


class ExfiltrationDetector(RuleBasedDetector):
    name = "exfiltration"
    category = "exfiltration"
