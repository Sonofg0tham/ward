"""Terminal-friendly report using Rich tables."""

from __future__ import annotations

import unicodedata

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


def _safe(value: str) -> Text:
    """Render attacker-controlled text as inert, visible characters.

    Three separate bugs shared one cause: every cell below used to be handed
    to Rich as a bare ``str``, which Rich parses as console markup.

    1. A crash. ``[INST] ignore previous instructions [/INST]`` - the exact
       payload Ward exists to catch - contains an unmatched closing tag, so
       ``console.print(table)`` raised ``MarkupError`` AFTER the engine had
       already decided FAIL. The traceback exited 1, and the Action reads
       exit 1 as WARN and passes the job. A correct detection became a green
       tick because of the reporter.
    2. Silent removal. ``[link=https://evil.example]docs[/link]`` rendered as
       "docs", so the human reading the report saw different text from the
       metadata that was actually scanned - and the exfiltration URL, the
       very thing that made it a finding, vanished from the evidence.
    3. Log rewriting. ESC bytes reached the terminal verbatim, so a payload
       ending ``\\x1b[2K\\x1b[1GSAFE: no findings`` could erase Ward's own
       output line in a CI log and print a reassuring lie in its place.

    ``Text()`` does not parse markup, which fixes 1 and 2. Escaping the C0/C1
    controls fixes 3. Control characters are escaped rather than dropped so
    the evidence still shows that something was hidden there; deleting them
    would let an attacker quietly shorten what a reviewer sees.
    """
    out: list[str] = []
    for ch in value:
        # Cc is C0/C1 controls (includes ESC, CR, NUL and the DEL-adjacent
        # range); Cf is the invisible formatting characters - zero-width
        # joiners, bidi overrides, the TAG block - which are frequently the
        # whole point of a finding and must never render as nothing.
        if unicodedata.category(ch) in ("Cc", "Cf"):
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return Text("".join(out))


def render_pretty(report: ScanReport, console: Console | None = None) -> None:
    """Print a human-friendly report to the console."""
    console = console or Console()

    header = Text()
    header.append("target: ", style="bold")
    # Text.append does not parse markup, but the target still reaches a
    # terminal: it is a branch name or a PR reference, both attacker-chosen.
    header.append_text(_safe(report.target))
    header.append("\n")
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
            _safe(finding.rule_id),
            _safe(finding.surface),
            _safe(finding.location or "-"),
            _safe(finding.evidence),
        )
    console.print(table)

    if report.verdict is not Verdict.PASS:
        console.print(
            "\n[bold]Next step:[/bold] run [cyan]ward explain <rule-id>[/cyan] for "
            "remediation guidance on any of the rules above."
        )
