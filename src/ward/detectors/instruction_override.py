"""Detects classic 'ignore previous instructions' style overrides."""

from __future__ import annotations

from .base import RuleBasedDetector


class InstructionOverrideDetector(RuleBasedDetector):
    name = "instruction_override"
    category = "instruction_override"
