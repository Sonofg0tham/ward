"""Detectors. Each one screens ScanInput objects against a rule category."""

from .ai_tool_specific import AIToolSpecificDetector
from .base import Detector, RuleBasedDetector
from .exfiltration import ExfiltrationDetector
from .instruction_override import InstructionOverrideDetector
from .obfuscation import ObfuscationDetector
from .role_manipulation import RoleManipulationDetector
from .tool_call_injection import ToolCallInjectionDetector

ALL_DETECTOR_CLASSES: tuple[type[Detector], ...] = (
    InstructionOverrideDetector,
    ObfuscationDetector,
    ToolCallInjectionDetector,
    RoleManipulationDetector,
    ExfiltrationDetector,
    AIToolSpecificDetector,
)

__all__ = [
    "Detector",
    "RuleBasedDetector",
    "InstructionOverrideDetector",
    "ObfuscationDetector",
    "ToolCallInjectionDetector",
    "RoleManipulationDetector",
    "ExfiltrationDetector",
    "AIToolSpecificDetector",
    "ALL_DETECTOR_CLASSES",
]
