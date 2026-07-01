"""Ward: pre-agent metadata scanner for prompt injection.

Public API (SDK use):

    from ward import build_input, scan_inputs, load_rule_pack
    from ward import Severity, Verdict, ScanInput, Finding, ScanReport

    pack = load_rule_pack()
    inputs = [build_input("pr_body", untrusted_text, location="user-input")]
    report = scan_inputs(inputs, pack, target="my-agent")
    if report.verdict is not Verdict.PASS:
        raise RuntimeError(f"Refusing to ingest: {report.findings}")

See README.md for the full SDK usage guide.
"""

from .core.engine import build_input, scan_inputs
from .core.models import Finding, ScanInput, ScanReport, Severity, Surface, Verdict
from .core.rules import RulePack, load_rule_pack

__version__ = "0.1.3"

__all__ = [
    "Finding",
    "RulePack",
    "ScanInput",
    "ScanReport",
    "Severity",
    "Surface",
    "Verdict",
    "__version__",
    "build_input",
    "load_rule_pack",
    "scan_inputs",
]
