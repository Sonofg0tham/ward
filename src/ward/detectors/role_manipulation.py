"""Detects tokenizer role tags and 'you are now ...' takeover attempts."""

from __future__ import annotations

from .base import RuleBasedDetector


class RoleManipulationDetector(RuleBasedDetector):
    name = "role_manipulation"
    category = "role_manipulation"
