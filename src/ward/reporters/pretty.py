"""Terminal-friendly report using Rich tables."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..core.models import ScanReport, Severity, Verdict

_SEVERITY_COLOUR = {
    Severity.INFO: "blue",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_VERDICT_COLOUR = {
    Verdict.PASS: "green",
    Verdict.WARN: "yellow",
    Verdict.FAIL: "red",
}


def render_pretty(report: ScanReport, console: Console | None = None) -> None:
    """Print a human-friendly report to the console."""
    console = console or Console()

    header = Text()
    header.append(f"target: {report.target}\n", style="bold")
    header.append(f"findings: {len(report.findings)}\n")
    header.append(f"threshold: {report.threshold.value}  fail-on: {report.fail_on.value}\n")
    header.append("verdict: ")
    header.append(report.verdict.value.upper(), style=_VERDICT_COLOUR[report.verdict])
    console.print(Panel.fit(header, title="Ward scan", border_style="blue"))

    if not report.findings:
        console.print("[green]No injection patterns detected.[/green]")
        return

    table = Table(show_lines=True, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Surface", no_wrap=True)
    table.add_column("Location")
    table.add_column("Evidence")

    for finding in sorted(report.findings, key=lambda f: (-f.severity.rank, f.rule_id)):
        sev_style = _SEVERITY_COLOUR[finding.severity]
        table.add_row(
            Text(finding.severity.value.upper(), style=sev_style),
            finding.rule_id,
            finding.surface,
            finding.location or "-",
            finding.evidence,
        )
    console.print(table)

    if report.verdict is not Verdict.PASS:
        console.print(
            "\n[bold]Next step:[/bold] run [cyan]ward explain <rule-id>[/cyan] for "
            "remediation guidance on any of the rules above."
        )
