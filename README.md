<!-- ward-allow-file: io.*, role.*, exf.*, tool.*, ait.*, obf.* -->

# Ward

> Pre-agent metadata scanner. Catches prompt injection in branch names,
> commit messages, PR titles, file names, and other untrusted strings
> before they reach an AI code reviewer.

Ward is a CLI and a GitHub Action. It screens the metadata an AI agent
ingests before any LLM-based reviewer, SAST agent, or IaC scanner sees
it. The job: catch prompt injection attempts embedded in the places that
traditional security tools ignore.

## Why this exists

Throughout early 2026, AI code-review agents were attacked through
metadata that traditional security tools treat as inert. The
attack class is documented in:

- The **ambient-code / CLAUDE.md prompt-injection** disclosure
  (Feb 2026), in which an attacker replaced `CLAUDE.md` to direct
  the reviewer agent to vandalise the repo and post a fake
  approval. Caught by Claude.
- The **Claude Code GitHub Action CVE** (disclosed June 2026,
  fixed in Claude Code 2.1.128), where a crafted issue body
  recovered the agent into executing commands that leaked
  environment variables.
- Snyk's **"Clinejection"** writeup, where a single GitHub issue
  title containing a prompt-injection payload triggered an AI
  reviewer (Cline) to publish malicious npm packages.
- The **"hackerbot-claw" GitHub Actions supply chain attacks**
  (Feb 2026), which compromised Microsoft's `ai-discovery-agent`
  via branch-name injection and DataDog's `iac-scanner` via
  filename injection. Those were bash-into-workflow attacks
  rather than prompt injection, but they prove the metadata-as-
  attack-surface trend.

The pattern across all of them: payloads land in places that
SAST, secret scanners, and prompt firewalls don't look.

The existing security stack does not help here:

- **SAST scanners** ignore branch names and commit messages. Those have
  never been an attack surface before.
- **Secret scanners** look for credentials, not instructions.
- **Prompt firewalls** (Lakera, LlamaFirewall, BoltClaw) sit at the LLM
  boundary inside the agent. By the time they see the text, it is already
  in the context window.
- **OWASP ASI Top 10** names the pattern (ASI01, goal hijack via untrusted
  input) but does not ship tooling.

Ward sits earlier. It runs against the surface area that attackers
actually use, before any LLM has a chance to act on it.

## Where Ward fits in

| Tool | Layer | Catches |
|------|-------|---------|
| **Ward** | Before the agent reads input | Prompt injection in branch names, file names, commit messages, PR titles, PR descriptions, code comments, README files |
| **Lakera Guard** | LLM boundary | Prompt injection in the prompt itself, jailbreaks, off-topic queries |
| **LlamaFirewall** | LLM boundary | Prompt injection, alignment violations, output policy enforcement |
| **BoltClaw** | Agent configuration | Tampering with agent system prompts, tool allowlists, MCP configs |
| **SAST / secret scanners** | Source code | Vulnerabilities and credentials in the code itself |

Ward is one layer. It is not a replacement for the others. Defence in
depth still applies.

## What Ward catches

Six detector categories, 25+ rules out of the box:

- **Instruction overrides** ("ignore previous instructions", "your new
  task is...", fake `[SYSTEM]` blocks).
- **Role manipulation** (tokenizer tags like `<|im_start|>system`,
  "developer mode", DAN-style activation).
- **Obfuscation** (zero-width unicode, RTL override, base64 blobs in
  unusual fields, hex blobs, HTML comments).
- **Tool-call injection** (fake `<tool_call>` wrappers, JSON tool-call
  objects, `mcp://` URIs, shell metacharacters in names).
- **Exfiltration prompts** (instructions to POST findings to a URL,
  include secrets, encode data in DNS queries).
- **AI tool-specific quirks** (Anthropic Human / Assistant tags, Cursor
  command palette, Antigravity tool schemas, Copilot slash commands).

## Install

```bash
pipx install ward-scanner
```

Verify the install:

```bash
ward version
```

## Use

### Scan a PR by reference

```bash
export GITHUB_TOKEN=ghp_...
ward scan-pr sonofg0tham/ward#42
```

Reads the PR title, body, head branch name, commit messages, and changed
file paths through the GitHub API. Never reads the file contents.

### Scan local git state

```bash
ward scan-local
```

Walks the working tree, scans the current branch name, the last 20
commit messages, tag names, every tracked file's path, and the
top-of-file content of any `.md`, `.txt`, `.rst`, and source files.

### Scan a single string

```bash
echo "feat/ignore-previous-instructions" | ward scan-stdin --surface branch_name
```

Every other Ward command is built on this one. Pipe whatever string you
want through it.

### Other commands

```bash
ward scan-branch  feat/ignore-previous-instructions
ward scan-commit  HEAD
ward explain      io.ignore_previous
```

### Output formats

```bash
ward scan-local --format pretty   # default, terminal table
ward scan-local --format json     # machine-readable
ward scan-local --format sarif    # GitHub Code Scanning compatible
```

### Severity thresholds

```bash
# Drop anything below MEDIUM, only FAIL on CRITICAL.
ward scan-local --severity-threshold medium --fail-on critical
```

Exit codes:

- `0` PASS, no findings above the threshold.
- `1` WARN, findings exist but none reached the fail-on severity.
- `2` FAIL, at least one finding at or above fail-on.

## Run the adversarial lab

Ward ships with a built-in lab that runs each scripted attack scenario
through two pipelines (unprotected and Ward-protected) and produces a
Markdown report you can paste into a blog post or PR comment:

```bash
ward lab attack
# Wrote lab report: ward-lab-report.md
# Blocked by Ward: 5/5 scenarios.
```

The mock reviewer agent does not call an LLM. The lab demonstrates
whether the untrusted instruction would have reached the agent's
context window, not what the LLM would have done with it. Wiring in a
real reviewer is the next step.

Flags: `--output <path>`, `--no-write` (print to stdout),
`--fail-on <severity>`.

## Pre-commit hook

If you use the [pre-commit](https://pre-commit.com/) framework, drop
this into your `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/sonofg0tham/ward
  rev: v0.1.0
  hooks:
    - id: ward-scan-local
      args: [--fail-on, high]
```

Ward then runs on every `git commit` and `git push`, screening your
branch name, commit messages, and tracked documentation files for
injection patterns. Stops you committing a poisoned PR before it ever
reaches GitHub.

Other hook ids: `ward-scan-stdin` (designed for the `commit-msg`
stage, screens the message you're typing), `ward-selftest` (manual,
useful as a CI gate).

## GitHub Action

Add it to a workflow in three lines:

```yaml
- uses: sonofg0tham/ward/action@v1
  with:
    fail-on: high
```

A fuller example that uploads SARIF to the GitHub Security tab:

```yaml
name: Ward
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  ward:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: sonofg0tham/ward/action@v1
        with:
          fail-on: high
          format: sarif
          upload-sarif: true
```

## Use Ward as a Python SDK

If you are building an agentic system (CrewAI, AutoGen, LangGraph, your own
loop) and want to screen text before it reaches the model, import Ward
directly:

```python
from ward import build_input, scan_inputs, load_rule_pack, Verdict

# Load the bundled rule pack once at startup.
pack = load_rule_pack()

def safe_ingest(untrusted_text: str) -> str:
    inputs = [build_input("pr_body", untrusted_text, location="user-input")]
    report = scan_inputs(inputs, pack, target="my-agent")
    if report.verdict is not Verdict.PASS:
        flagged = [f.rule_id for f in report.findings]
        raise ValueError(f"Refusing to ingest untrusted text: {flagged}")
    return untrusted_text
```

The 13 supported surface types (`branch_name`, `commit_message`, `pr_body`,
`file_content`, ...) let you tune which rules apply. A LangGraph tool that
ingests web search results would use `pr_body` or `file_content`; a CrewAI
agent reading a filename would use `file_name`.

### Inside a LangGraph node

```python
from ward import build_input, scan_inputs, load_rule_pack, Verdict

_pack = load_rule_pack()

def web_search_node(state):
    text = state["search_result"]
    report = scan_inputs(
        [build_input("file_content", text, location="search")],
        _pack,
        target="search_result",
    )
    if report.verdict is not Verdict.PASS:
        state["search_result"] = "(blocked by Ward)"
        state["ward_findings"] = [f.rule_id for f in report.findings]
    return state
```

### Inside a CrewAI tool

```python
from crewai.tools import BaseTool
from ward import build_input, scan_inputs, load_rule_pack, Verdict

class GuardedFileReader(BaseTool):
    name = "read_file"
    description = "Read a file, screened by Ward."
    _pack = load_rule_pack()

    def _run(self, path: str) -> str:
        text = open(path).read()
        report = scan_inputs(
            [build_input("file_content", text, location=path)],
            self._pack,
            target=path,
        )
        if report.verdict is not Verdict.PASS:
            return f"(refused: Ward flagged {[f.rule_id for f in report.findings]})"
        return text
```

## Custom rule packs

Drop a directory of YAML files alongside your repo and point Ward at it:

```bash
ward scan-local --rule-pack ./security/ward-rules
```

Each YAML file is a list of rules. Schema is documented in
[`src/ward/rules/instruction_overrides.yaml`](src/ward/rules/instruction_overrides.yaml).

## Ignoring whole paths with `.wardignore`

Some directories - test fixtures, security research notes, rule packs
themselves - are intentionally adversarial and should not be scanned for
content. Drop a `.wardignore` at the repo root with fnmatch-style globs:

```
# .wardignore
tests/fixtures/**/*    # adversarial by design
security/research/*    # writeup of past attacks
docs/threat-models/*
```

Filenames in ignored paths are STILL scanned (a malicious filename
remains suspicious even inside an ignored directory). Only the content
scan is suppressed. Ward's own repo uses this to exclude its own source
tree from self-scanning.

## Suppressing rules in documentation

Security-research docs (Ward's own README included) need to *talk about*
the attack strings without firing the scanner. Drop this directive near
the top of any documentation file:

```html
<!-- ward-allow-file: io.*, role.tokenizer_tag -->
```

The directive accepts rule ids or fnmatch-style globs, comma-separated.
It is only honoured on `file_content` and `code_comment` surfaces, never
on branch names, commit messages, PR titles, or PR bodies. That's the
intentional asymmetry: attackers cannot suppress detection from inside
the text Ward is trying to screen.

Supported comment styles for the directive:

```html
<!-- ward-allow-file: io.* -->     <!-- HTML / Markdown -->
# ward-allow-file: io.*            # Python / Bash / YAML
// ward-allow-file: io.*           // JS / TS / Go / Rust / Java
/* ward-allow-file: io.* */        /* C / CSS */
```

## Evasion resistance

Ward feeds detectors a normalised view of the text plus several
alternative forms designed to defeat common evasion tricks:

- **Leetspeak** — `1gn0r3 4ll pr3v10us` becomes `ignore all previous`.
- **Intra-word separators** — `i.g.n.o.r.e` and `i-g-n-o-r-e` collapse
  to `ignore`.
- **Repeated letters** — `ignooooore` and `previousssss` collapse to
  `ignore` and `previous`. Two collapse variants are tried (collapse
  to 1 letter and collapse to 2) so naturally-doubled English words
  like `all`, `free`, `see` survive.
- **Zero-width unicode** — stripped before regex match.
- **NFKC** — fullwidth and compatibility characters fold to ASCII.
- **Base64 / hex blocks** — decoded and re-scanned.
- **Identifier delimiters** — `-`, `_`, `/`, `.` in branch and file
  names normalise to spaces.

**Known limitation:** the all-single-space case (`i g n o r e p r e v i
o u s`) is not handled, because the original word boundaries cannot be
recovered reliably from spaced-out singletons. Multi-space separators
between words (`i g n o r e   p r e v i o u s`) are still ambiguous and
out of scope for v0.1.

## Threat model

Ward is a pattern-matching tool. It catches the attack class documented
in OWASP ASI Top 10 (ASI01) and in the early-2026 incidents above.

It does **not** catch:

- Novel zero-day injection techniques that match no rule.
- Attacks embedded in non-text formats (images, PDFs, audio).
- Attacks on the model itself once context has been built. That is a
  prompt firewall's job.
- Vulnerabilities in the code being reviewed. That is SAST's job.

See [SECURITY.md](SECURITY.md) for the full threat model and the
vulnerability disclosure process.

## Telemetry

Ward sends none. No phone home, no anonymous stats, no metrics
collection. The only outbound network calls Ward ever makes are the
GitHub API requests you explicitly trigger via `ward scan-pr`.

## Development

```bash
git clone https://github.com/sonofg0tham/ward
cd ward
python -m venv .venv && source .venv/bin/activate    # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
pytest
```

Coverage target is 75% and current trunk runs at 83%.

## Licence

MIT. See [LICENSE](LICENSE).
