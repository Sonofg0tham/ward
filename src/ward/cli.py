"""Ward command-line interface.

The engine entry-point is ``ward.core.engine.scan_inputs``. Every subcommand
below is a thin wrapper that gathers untrusted text, builds ``ScanInput``
records, and hands them off.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .core.engine import build_input, scan_inputs
from .core.git_metadata import (
    CODE_SUFFIXES,
    DOC_SUFFIXES,
    commit_message,
    current_branch,
    head_sha,
    recent_commits,
    tag_names,
    walk_tracked_files,
)
from .core.github_api import GitHubError, fetch_pr_metadata, parse_pr_ref
from .core.models import ScanInput, ScanReport, Severity, Surface
from .core.rules import RulePack, load_rule_pack
from .reporters import render_json, render_pretty, render_sarif

app = typer.Typer(
    name="ward",
    help="Pre-agent metadata scanner. Catches prompt injection before it reaches an AI code reviewer.",
    add_completion=False,
    no_args_is_help=True,
)

lab_app = typer.Typer(
    name="lab",
    help="Adversarial lab harness: run a mock reviewer agent vs prompt injection.",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(lab_app, name="lab")

# --- global options ---------------------------------------------------------

OutputFormat = Annotated[
    str,
    typer.Option(
        "--format",
        "-f",
        help="Output format: pretty | json | sarif",
        case_sensitive=False,
    ),
]
ThresholdOption = Annotated[
    str,
    typer.Option(
        "--severity-threshold",
        help="Drop findings below this severity (info|low|medium|high|critical).",
    ),
]
FailOnOption = Annotated[
    str,
    typer.Option(
        "--fail-on",
        help="Findings at or above this severity make the run FAIL (info|low|medium|high|critical).",
    ),
]
RulePackOption = Annotated[
    Path | None,
    typer.Option(
        "--rule-pack",
        help="Custom rule pack directory. Defaults to the bundled rules.",
    ),
]


def _parse_severity(value: str, *, flag: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError as exc:
        valid = ", ".join(s.value for s in Severity)
        raise typer.BadParameter(f"{flag} must be one of: {valid}") from exc


def _emit(
    report: ScanReport,
    *,
    fmt: str,
    console: Console,
) -> int:
    fmt_lower = fmt.lower()
    if fmt_lower == "pretty":
        render_pretty(report, console)
    elif fmt_lower == "json":
        typer.echo(render_json(report))
    elif fmt_lower == "sarif":
        typer.echo(render_sarif(report))
    else:
        raise typer.BadParameter(f"--format must be pretty|json|sarif (got {fmt!r})")
    return report.exit_code


def _run(
    inputs: list[ScanInput],
    *,
    target: str,
    fmt: str,
    threshold: str,
    fail_on: str,
    rule_pack: Path | None,
) -> int:
    pack: RulePack = load_rule_pack(rule_pack)
    sev_threshold = _parse_severity(threshold, flag="--severity-threshold")
    sev_fail = _parse_severity(fail_on, flag="--fail-on")
    report = scan_inputs(
        inputs,
        pack,
        target=target,
        fail_on=sev_fail,
        threshold=sev_threshold,
    )
    return _emit(report, fmt=fmt, console=Console())


# --- subcommands ------------------------------------------------------------


@app.command("scan-stdin")
def scan_stdin(
    surface: Annotated[
        str,
        typer.Option(
            "--surface",
            help=(
                "Treat stdin as this kind of metadata. Choose the closest match: "
                "branch_name, commit_message, pr_title, pr_body, file_content, etc. "
                "Affects which rules fire."
            ),
        ),
    ] = "stdin",
    fmt: OutputFormat = "pretty",
    threshold: ThresholdOption = "low",
    fail_on: FailOnOption = "high",
    rule_pack: RulePackOption = None,
) -> None:
    """Scan whatever is piped to stdin. The base command every other one wraps."""
    text = sys.stdin.read()
    inputs = [build_input(_cast_surface(surface), text, location="stdin")]
    code = _run(
        inputs,
        target="stdin",
        fmt=fmt,
        threshold=threshold,
        fail_on=fail_on,
        rule_pack=rule_pack,
    )
    raise typer.Exit(code=code)


@app.command("scan-branch")
def scan_branch(
    branch: Annotated[str, typer.Argument(help="The branch name to scan in isolation.")],
    fmt: OutputFormat = "pretty",
    threshold: ThresholdOption = "low",
    fail_on: FailOnOption = "high",
    rule_pack: RulePackOption = None,
) -> None:
    """Scan a single branch name."""
    inputs = [build_input("branch_name", branch, location=f"branch:{branch}")]
    code = _run(
        inputs,
        target=f"branch:{branch}",
        fmt=fmt,
        threshold=threshold,
        fail_on=fail_on,
        rule_pack=rule_pack,
    )
    raise typer.Exit(code=code)


@app.command("scan-commit")
def scan_commit(
    sha: Annotated[str, typer.Argument(help="The commit SHA to scan.")],
    repo: Annotated[
        Path, typer.Option("--repo", help="Path to the git repo. Defaults to the cwd.")
    ] = Path("."),
    fmt: OutputFormat = "pretty",
    threshold: ThresholdOption = "low",
    fail_on: FailOnOption = "high",
    rule_pack: RulePackOption = None,
) -> None:
    """Scan a single commit's message."""
    message = commit_message(repo, sha)
    if not message:
        typer.echo(f"Could not read commit {sha} from {repo}", err=True)
        raise typer.Exit(code=2)
    inputs = [build_input("commit_message", message, location=f"commit:{sha}")]
    code = _run(
        inputs,
        target=f"commit:{sha}",
        fmt=fmt,
        threshold=threshold,
        fail_on=fail_on,
        rule_pack=rule_pack,
    )
    raise typer.Exit(code=code)


@app.command("scan-local")
def scan_local(
    repo: Annotated[
        Path, typer.Option("--repo", help="Path to the git repo. Defaults to the cwd.")
    ] = Path("."),
    commit_limit: Annotated[
        int, typer.Option("--commits", help="How many recent commit messages to scan.")
    ] = 20,
    fmt: OutputFormat = "pretty",
    threshold: ThresholdOption = "low",
    fail_on: FailOnOption = "high",
    rule_pack: RulePackOption = None,
) -> None:
    """Scan the local git working tree: branch, recent commits, tags, doc files."""
    inputs: list[ScanInput] = []
    branch = current_branch(repo)
    if branch:
        inputs.append(build_input("branch_name", branch, location=f"branch:{branch}"))
    for sha, msg in recent_commits(repo, limit=commit_limit):
        inputs.append(build_input("commit_message", msg, location=f"commit:{sha[:8]}"))
    for tag in tag_names(repo):
        inputs.append(build_input("tag_name", tag, location=f"tag:{tag}"))
    for path in walk_tracked_files(repo):
        suffix = path.suffix.lower()
        relname = str(path.relative_to(repo))
        inputs.append(build_input("file_name", relname, location=relname))
        if suffix in DOC_SUFFIXES:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            inputs.append(build_input("file_content", content, location=relname))
        elif suffix in CODE_SUFFIXES:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Top-of-file comments only - cheap, high signal.
            top = "\n".join(content.splitlines()[:40])
            inputs.append(build_input("code_comment", top, location=f"{relname}:top"))

    target = f"local:{repo}"
    sha = head_sha(repo)
    if sha:
        target += f"@{sha[:8]}"
    code = _run(
        inputs,
        target=target,
        fmt=fmt,
        threshold=threshold,
        fail_on=fail_on,
        rule_pack=rule_pack,
    )
    raise typer.Exit(code=code)


@app.command("scan-pr")
def scan_pr(
    ref: Annotated[
        str, typer.Argument(help="PR reference, e.g. 'sonofg0tham/ward#42'.")
    ],
    fmt: OutputFormat = "pretty",
    threshold: ThresholdOption = "low",
    fail_on: FailOnOption = "high",
    rule_pack: RulePackOption = None,
) -> None:
    """Scan a PR's metadata via the GitHub API.

    Reads PR title, body, head branch name, commit messages, and file paths
    from the diff. Never reads the file contents from the PR. Requires
    ``GITHUB_TOKEN`` (or ``GH_TOKEN``) for private repos and for any
    meaningful rate limit on public ones.
    """
    try:
        owner, repo, number = parse_pr_ref(ref)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc
    try:
        meta = fetch_pr_metadata(owner, repo, number)
    except GitHubError as exc:
        typer.echo(f"GitHub error: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    inputs: list[ScanInput] = [
        build_input("pr_title", meta.title, location=f"{ref}#title"),
        build_input("pr_body", meta.body, location=f"{ref}#body"),
        build_input("branch_name", meta.head_ref, location=f"branch:{meta.head_ref}"),
    ]
    for sha, msg in meta.commit_messages:
        inputs.append(build_input("commit_message", msg, location=f"commit:{sha[:8]}"))
    for path in meta.changed_file_paths:
        inputs.append(build_input("file_name", path, location=path))

    code = _run(
        inputs,
        target=ref,
        fmt=fmt,
        threshold=threshold,
        fail_on=fail_on,
        rule_pack=rule_pack,
    )
    raise typer.Exit(code=code)


@app.command("explain")
def explain(
    rule_id: Annotated[str, typer.Argument(help="The rule id, e.g. 'io.ignore_previous'.")],
    rule_pack: RulePackOption = None,
) -> None:
    """Print a plain-English explanation of a rule."""
    pack = load_rule_pack(rule_pack)
    rule = pack.by_id(rule_id)
    if rule is None:
        # Heuristic rules live in code rather than YAML.
        from .detectors.obfuscation import ObfuscationDetector  # local import to avoid cycles

        heuristic = _heuristic_rule_doc(rule_id, ObfuscationDetector)
        if heuristic:
            typer.echo(heuristic)
            return
        typer.echo(f"Unknown rule id: {rule_id}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"id:          {rule.id}")
    typer.echo(f"category:    {rule.category}")
    typer.echo(f"severity:    {rule.severity.value}")
    typer.echo(f"description: {rule.description}")
    typer.echo(f"applies to:  {', '.join(sorted(rule.surfaces)) or 'all surfaces'}")
    typer.echo("patterns:")
    for p in rule.patterns:
        typer.echo(f"  - {p.pattern}")
    if rule.remediation:
        typer.echo(f"remediation: {rule.remediation}")
    if rule.references:
        typer.echo("references:")
        for r in rule.references:
            typer.echo(f"  - {r}")


@app.command("update-rules")
def update_rules() -> None:
    """Pull the latest community rule pack.

    In v0.1 the rule pack ships inside the wheel. This command exists so the
    interface is stable for v0.2, but currently it only prints a hint.
    """
    typer.echo(
        "Ward 0.1 ships rules inside the wheel. To update, upgrade Ward itself:\n"
        "  pipx upgrade ward-scanner\n\n"
        "Community rule-pack distribution will land in 0.2."
    )


@app.command("version")
def version() -> None:
    """Print the installed Ward version."""
    typer.echo(__version__)


@app.command("attack-demo")
def attack_demo(
    scenario: Annotated[
        str,
        typer.Option(
            "--scenario",
            help="Run a single scenario by name. Use --list to see them all.",
        ),
    ] = "",
    list_only: Annotated[
        bool, typer.Option("--list", help="List available scenarios without running them.")
    ] = False,
    rule_pack: RulePackOption = None,
) -> None:
    """Run scripted adversarial scenarios against Ward.

    Each scenario tells the story of one real attack class, shows the
    untrusted text a reviewer agent would have ingested, then shows what
    Ward catches. This is the one-command portfolio demonstration.
    """
    from .demo import DEMOS  # local import to keep CLI startup snappy

    if list_only:
        for d in DEMOS:
            typer.echo(f"{d.name:<22}  {d.title}")
        return

    chosen = DEMOS
    if scenario:
        chosen = tuple(d for d in DEMOS if d.name == scenario)
        if not chosen:
            typer.echo(f"Unknown scenario: {scenario}", err=True)
            typer.echo("Run 'ward attack-demo --list' to see available scenarios.", err=True)
            raise typer.Exit(code=2)

    pack = load_rule_pack(rule_pack)
    console = Console()
    overall_caught = 0
    overall_total = 0

    for idx, demo in enumerate(chosen, start=1):
        header = Text()
        header.append(f"Scenario {idx}/{len(chosen)}: ", style="bold")
        header.append(demo.title, style="bold yellow")
        console.print()
        console.print(Panel(header, border_style="yellow"))
        console.print(f"[italic]{demo.setup}[/italic]\n")

        # What the agent would see
        agent_view = Text()
        for inp in demo.inputs:
            agent_view.append(f"[{inp.surface}]\n", style="dim")
            agent_view.append(inp.text + "\n\n")
        console.print(
            Panel(
                agent_view,
                title="What the reviewer agent would ingest without Ward",
                border_style="red",
            )
        )

        # Run Ward
        inputs = [build_input(inp.surface, inp.text, location=demo.name) for inp in demo.inputs]
        report = scan_inputs(inputs, pack, target=demo.name)

        if report.findings:
            ward_table = Table(show_lines=False, header_style="bold")
            ward_table.add_column("Sev", no_wrap=True)
            ward_table.add_column("Rule", no_wrap=True)
            ward_table.add_column("Surface", no_wrap=True)
            ward_table.add_column("Evidence")
            for f in sorted(report.findings, key=lambda f: (-f.severity.rank, f.rule_id)):
                ward_table.add_row(
                    f.severity.value.upper(),
                    f.rule_id,
                    f.surface,
                    f.evidence[:80],
                )
            console.print(
                Panel(
                    ward_table,
                    title=f"What Ward catches  -  verdict: [green]{report.verdict.value.upper()}[/green]",
                    border_style="green",
                )
            )
            overall_caught += 1
        else:
            console.print(
                Panel(
                    "[red]Ward did not catch this scenario.[/red]",
                    title="What Ward catches",
                    border_style="red",
                )
            )

        console.print(f"[bold]Impact:[/bold] {demo.impact}")
        if demo.references:
            console.print(f"[dim]Reference: {demo.references[0]}[/dim]")
        overall_total += 1

    console.print()
    console.print(
        Panel.fit(
            f"Ward caught [bold green]{overall_caught}[/bold green] of "
            f"[bold]{overall_total}[/bold] scripted attack scenarios.",
            title="Summary",
            border_style="blue",
        )
    )
    raise typer.Exit(code=0 if overall_caught == overall_total else 2)


@app.command("selftest")
def selftest(
    rule_pack: RulePackOption = None,
) -> None:
    """Run Ward's built-in adversarial scenarios and report detection coverage.

    This is the one-command credibility check. Each scenario is a known
    attack pattern from OWASP ASI Top 10 or the March 2026 incidents. Ward
    scans them all and reports whether the expected rule fired.
    """
    from .selftest import CATEGORIES, SCENARIOS  # local import to keep startup snappy

    pack = load_rule_pack(rule_pack)
    console = Console()

    table = Table(
        title="Ward selftest - detection coverage",
        title_style="bold",
        show_lines=True,
    )
    table.add_column("Scenario", no_wrap=True, style="bold")
    table.add_column("Category", no_wrap=True)
    table.add_column("Surface", no_wrap=True)
    table.add_column("Expected rule", no_wrap=True)
    table.add_column("Result")

    per_category: dict[str, tuple[int, int]] = {c: (0, 0) for c in CATEGORIES}
    overall_pass = 0
    overall_total = 0

    for scenario in SCENARIOS:
        inputs = [build_input(scenario.surface, scenario.payload, location=scenario.name)]
        report = scan_inputs(inputs, pack, target=scenario.name)
        fired = {f.rule_id for f in report.findings}
        ok = scenario.expect_rule in fired
        verdict_cell = "[green]PASS[/green]" if ok else f"[red]MISS[/red] (got {sorted(fired) or 'nothing'})"
        table.add_row(
            scenario.name,
            scenario.category,
            scenario.surface,
            scenario.expect_rule,
            verdict_cell,
        )
        cat_pass, cat_total = per_category.get(scenario.category, (0, 0))
        per_category[scenario.category] = (cat_pass + (1 if ok else 0), cat_total + 1)
        overall_total += 1
        overall_pass += 1 if ok else 0

    console.print(table)

    summary = Table(title="Per-category summary", show_lines=False)
    summary.add_column("Category", style="bold")
    summary.add_column("Detected")
    summary.add_column("Coverage")
    for cat in CATEGORIES:
        passed, total = per_category[cat]
        if total == 0:
            summary.add_row(cat, "0 / 0", "-")
            continue
        pct = (passed / total) * 100
        colour = "green" if passed == total else "yellow" if passed > 0 else "red"
        summary.add_row(cat, f"{passed} / {total}", f"[{colour}]{pct:.0f}%[/{colour}]")
    console.print(summary)

    pct = (overall_pass / overall_total * 100) if overall_total else 0.0
    if overall_pass == overall_total:
        console.print(f"[green bold]Overall: {overall_pass} / {overall_total} ({pct:.0f}%) - all scenarios detected.[/green bold]")
        raise typer.Exit(code=0)
    console.print(f"[red bold]Overall: {overall_pass} / {overall_total} ({pct:.0f}%) - some scenarios missed.[/red bold]")
    raise typer.Exit(code=2)


# --- lab subcommand ---------------------------------------------------------


@lab_app.command("attack")
def lab_attack(
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Where to write the Markdown report. Defaults to 'ward-lab-report.md'.",
        ),
    ] = None,
    no_write: Annotated[
        bool,
        typer.Option("--no-write", help="Print the report to stdout instead of writing a file."),
    ] = False,
    fail_on: FailOnOption = "high",
    rule_pack: RulePackOption = None,
) -> None:
    """Run the mock-reviewer-vs-prompt-injection lab.

    Each bundled attack-demo scenario is run through two pipelines:
    unprotected (the agent ingests the raw text) and Ward-protected
    (Ward screens first). The output is a Markdown document you can
    paste into a blog post or PR comment.
    """
    from .lab import render_markdown, run_default_lab  # local import for snappy startup

    pack = load_rule_pack(rule_pack)
    sev_fail = _parse_severity(fail_on, flag="--fail-on")
    report = run_default_lab(pack)
    # Re-render fail-on into the report (run_default_lab uses HIGH; respect the CLI choice).
    report = type(report)(runs=report.runs, fail_on=sev_fail, generated_at=report.generated_at)
    markdown = render_markdown(report)
    if no_write:
        typer.echo(markdown)
    else:
        target = output or Path("ward-lab-report.md")
        target.write_text(markdown, encoding="utf-8")
        typer.echo(f"Wrote lab report: {target}")
        typer.echo(f"Blocked by Ward: {report.caught}/{report.total} scenarios.")
    raise typer.Exit(code=0 if report.caught == report.total else 2)


# --- helpers ----------------------------------------------------------------


_KNOWN_SURFACES: frozenset[str] = frozenset(
    {
        "branch_name",
        "tag_name",
        "commit_message",
        "commit_author",
        "file_name",
        "directory_name",
        "file_content",
        "code_comment",
        "pr_title",
        "pr_body",
        "issue_title",
        "issue_body",
        "stdin",
    }
)


def _cast_surface(value: str) -> Surface:
    if value not in _KNOWN_SURFACES:
        valid = ", ".join(sorted(_KNOWN_SURFACES))
        raise typer.BadParameter(f"--surface must be one of: {valid}")
    return value  # type: ignore[return-value]


def _heuristic_rule_doc(rule_id: str, _detector_cls: type) -> str | None:
    """Documentation for code-defined heuristic rules (no YAML row)."""
    docs = {
        "obf.bidi_override": (
            "obf.bidi_override\ncategory:    obfuscation\nseverity:    high\n"
            "Bidirectional unicode override characters can hide malicious text.\n"
            "See https://trojansource.codes/ for the canonical attack."
        ),
        "obf.zero_width": (
            "obf.zero_width\ncategory:    obfuscation\nseverity:    medium\n"
            "Zero-width characters can split keywords to evade naive filters."
        ),
        "obf.base64_blob": (
            "obf.base64_blob\ncategory:    obfuscation\nseverity:    medium\n"
            "Long base64 blocks in PR metadata or commit text are almost never legitimate."
        ),
        "obf.hex_blob": (
            "obf.hex_blob\ncategory:    obfuscation\nseverity:    low\n"
            "Long hex blocks in PR metadata can hide encoded instructions."
        ),
    }
    return docs.get(rule_id)


if __name__ == "__main__":  # pragma: no cover
    app()
