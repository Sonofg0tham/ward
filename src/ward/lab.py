"""Adversarial lab harness.

Runs the built-in attack-demo scenarios through two pipelines, side by
side, and produces a Markdown report:

1. **Unprotected** - the untrusted text is handed straight to a mock
   reviewer agent. The transcript records exactly what the agent would
   have ingested. This is the baseline.
2. **Ward in front** - the same text goes through Ward first. Findings
   are reported; anything at or above the configured fail-severity is
   blocked before the agent sees it.

The output is a Markdown document that can be pasted directly into a
blog post, a lab notebook, or a PR comment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from .core.engine import build_input, scan_inputs
from .core.models import Finding, ScanInput, Severity, Verdict
from .core.rules import RulePack
from .demo import DEMOS, DemoScenario


# --- mock reviewer agent ---------------------------------------------------


class MockReviewerAgent:
    """A deterministic stand-in for an LLM-based reviewer agent.

    It does NOT call an LLM. It returns a transcript describing what an
    agent would have done with the input. The point of the lab is to
    demonstrate that the untrusted text reached the agent's context, not
    to model agent behaviour.
    """

    name = "MockReviewer"

    def review(self, inputs: tuple[ScanInput, ...]) -> str:
        lines: list[str] = []
        lines.append(f"[{self.name}] Begin review session.")
        for inp in inputs:
            lines.append(f"[{self.name}] read({inp.surface}, len={len(inp.raw)}):")
            for raw_line in inp.raw.splitlines() or [inp.raw]:
                lines.append(f"    {raw_line}")
        lines.append(
            f"[{self.name}] (context window now populated. An LLM here would "
            "summarise and act on the above text.)"
        )
        return "\n".join(lines)

    def refuse(self, reason: str) -> str:
        return f"[{self.name}] Input rejected by Ward. Reason: {reason}"


# --- lab data --------------------------------------------------------------


@dataclass(frozen=True)
class LabRun:
    scenario: DemoScenario
    unprotected_transcript: str
    ward_findings: tuple[Finding, ...]
    ward_verdict: Verdict
    protected_transcript: str
    blocked_by_ward: bool


@dataclass(frozen=True)
class LabReport:
    runs: tuple[LabRun, ...]
    fail_on: Severity
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def caught(self) -> int:
        return sum(1 for r in self.runs if r.blocked_by_ward)

    @property
    def total(self) -> int:
        return len(self.runs)


# --- harness ---------------------------------------------------------------


def run_lab(
    scenarios: tuple[DemoScenario, ...],
    rule_pack: RulePack,
    *,
    fail_on: Severity = Severity.HIGH,
) -> LabReport:
    """Run every scenario through both pipelines and return a structured report."""
    agent = MockReviewerAgent()
    runs: list[LabRun] = []
    for scenario in scenarios:
        # Build inputs once - both pipelines see the same scan inputs so
        # the comparison is genuinely apples-to-apples.
        inputs = tuple(
            build_input(inp.surface, inp.text, location=scenario.name)
            for inp in scenario.inputs
        )

        # Unprotected pipeline: agent ingests directly.
        unprotected = agent.review(inputs)

        # Protected pipeline: Ward screens first.
        report = scan_inputs(inputs, rule_pack, target=scenario.name, fail_on=fail_on)
        blocked = report.verdict is Verdict.FAIL
        if blocked:
            rule_ids = sorted({f.rule_id for f in report.findings})
            protected = agent.refuse(f"Ward flagged {rule_ids}")
        else:
            protected = agent.review(inputs)

        runs.append(
            LabRun(
                scenario=scenario,
                unprotected_transcript=unprotected,
                ward_findings=report.findings,
                ward_verdict=report.verdict,
                protected_transcript=protected,
                blocked_by_ward=blocked,
            )
        )
    return LabReport(runs=tuple(runs), fail_on=fail_on)


# --- markdown rendering ----------------------------------------------------


def _h(level: int, text: str) -> str:
    return f"{'#' * level} {text}"


def _quote(text: str) -> str:
    return "\n".join(f"> {line}" if line else ">" for line in text.splitlines())


def render_markdown(report: LabReport) -> str:
    """Render a LabReport as a self-contained Markdown document."""
    out: list[str] = []
    out.append(_h(1, "Ward lab report: Reviewer Agent vs prompt injection"))
    out.append("")
    out.append(f"_Generated: {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}_")
    out.append("")
    out.append(f"- Scenarios run: **{report.total}**")
    out.append(f"- Blocked by Ward: **{report.caught}** ({report.caught * 100 // max(report.total, 1)}%)")
    out.append(
        f"- Would have reached unprotected agent: **{report.total}** "
        f"(by definition - the scenarios are designed to)"
    )
    out.append(f"- Ward fail threshold: `{report.fail_on.value}`")
    out.append("")
    out.append("## Method")
    out.append("")
    out.append(
        "Each scenario was run through two pipelines. The **unprotected** "
        "pipeline hands the untrusted text straight to a deterministic mock "
        "reviewer agent that records what it would have ingested. The "
        "**protected** pipeline runs Ward first; anything at or above the "
        f"`{report.fail_on.value}` severity is blocked before the agent sees it."
    )
    out.append("")
    out.append(
        "The mock reviewer does not call an LLM. The point of this lab is to "
        "show whether the untrusted instruction reaches an agent's context "
        "window. What the LLM would have done with it is the focus of a real "
        "Reviewer Agent integration, which is the next step."
    )
    out.append("")

    for idx, run in enumerate(report.runs, start=1):
        out.append(_h(2, f"Scenario {idx}: {run.scenario.title}"))
        out.append("")
        out.append(f"_{run.scenario.setup}_")
        out.append("")
        out.append(_h(3, "Untrusted inputs"))
        out.append("")
        for inp in run.scenario.inputs:
            out.append(f"- **{inp.surface}**:")
            out.append("")
            out.append(_quote(inp.text))
            out.append("")

        out.append(_h(3, "Pipeline A: unprotected"))
        out.append("")
        out.append("```")
        out.append(run.unprotected_transcript)
        out.append("```")
        out.append("")

        out.append(_h(3, "Pipeline B: Ward in front"))
        out.append("")
        if run.ward_findings:
            out.append(f"Ward verdict: **{run.ward_verdict.value.upper()}**")
            out.append("")
            out.append("| Severity | Rule | Surface | Evidence |")
            out.append("|----------|------|---------|----------|")
            for f in sorted(run.ward_findings, key=lambda f: (-f.severity.rank, f.rule_id)):
                evidence = f.evidence.replace("|", "\\|").replace("\n", " ")[:80]
                out.append(
                    f"| {f.severity.value.upper()} | `{f.rule_id}` | "
                    f"{f.surface} | {evidence} |"
                )
            out.append("")
        else:
            out.append("Ward verdict: **PASS** (no findings)")
            out.append("")
        out.append("Mock reviewer transcript:")
        out.append("")
        out.append("```")
        out.append(run.protected_transcript)
        out.append("```")
        out.append("")

        out.append(_h(3, "Impact if Ward were absent"))
        out.append("")
        out.append(run.scenario.impact)
        if run.scenario.references:
            out.append("")
            out.append(f"Reference: {run.scenario.references[0]}")
        out.append("")

    out.append(_h(2, "Conclusion"))
    out.append("")
    if report.caught == report.total:
        out.append(
            "Ward blocked every scripted attack scenario before the reviewer "
            "agent's context window was populated. Each attack is drawn from "
            "OWASP ASI Top 10 or the March 2026 GitHub supply-chain incidents."
        )
    else:
        missed = report.total - report.caught
        out.append(
            f"Ward blocked {report.caught}/{report.total} scenarios; "
            f"{missed} reached the agent. The gaps are the next priority "
            "for rule-pack development."
        )
    out.append("")
    out.append("---")
    out.append("")
    out.append("_This report was generated by `ward lab attack`._")
    return "\n".join(out)


def run_default_lab(rule_pack: RulePack) -> LabReport:
    """Convenience wrapper that runs all bundled DEMOS."""
    return run_lab(DEMOS, rule_pack)
