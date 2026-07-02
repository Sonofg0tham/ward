<!-- ward-allow-file: io.*, role.*, exf.*, tool.*, ait.*, obf.* -->

# Security Policy

## Threat Model

Ward is a pattern-matching tool that screens the metadata an AI agent ingests
before that content reaches an LLM-based code reviewer, SAST agent, or IaC
scanner. It catches the attack class documented in OWASP ASI Top 10 (ASI01,
goal hijack via untrusted input) and demonstrated in real 2026 incidents:
the ambient-code / CLAUDE.md prompt-injection compromise (Feb 2026), the
Claude Code GitHub Action CVE (disclosed Jun 2026, fixed in 2.1.128), and
Snyk's "Clinejection" issue-title attack against Cline.

### What Ward catches

- Direct instruction-override strings ("ignore previous instructions", "your
  new task is...") embedded in branch names, commit messages, file names, PR
  titles, PR descriptions, code comments, and Markdown content.
- Role-manipulation tokens such as `<|im_start|>system`, fake tool-call
  syntax, and Anthropic / Cursor / Antigravity-specific role markers.
- Obfuscation patterns: zero-width unicode, RTL override (U+202E), long
  base64 blocks in unusual fields, and hex-encoded payloads.
- Tool-call injection: fake JSON tool-call objects and MCP-style URIs in
  free-form text.
- Exfiltration prompts that instruct an agent to POST data to a URL or
  include secrets in its output.

### What Ward does not catch

#### Out of scope by design

- Attacks on the LLM itself once context has been built. That is a prompt
  firewall's job (Lakera, LlamaFirewall, NVIDIA NeMo Guardrails, Microsoft
  Prompt Shields). Ward sits earlier in the pipeline.
- Vulnerabilities in the code being reviewed. That is SAST's job. Ward does
  not compete with SAST.
- Agent-configuration tampering. That is BoltClaw's and AgentShield's job.
  Ward protects agent input, those tools protect agent configuration.

#### Known limitations of the current rule pack (regex-shaped)

Ward's tier 1 is regex-driven. That ceiling is real and is documented here
so you do not adopt Ward expecting protection it cannot give. The optional
LLM judge tier (`ward judge` / `ward bench --judge`, see the README) is the
intended answer for the semantic classes below - enable it where you need
recall beyond what regex can reach:

- **GCG / adversarial-suffix attacks** (Zou et al). Gibberish optimised
  suffixes with no natural-language shape. Regex misses entirely; the
  judge tier is the intended mitigation.
- **AutoDAN / PAIR optimised paraphrases.** Semantic, no canonical phrase
  for a regex to anchor on. Judge tier territory.
- **Crescendo / multi-turn gradual jailbreaks.** Ward is stateless per
  surface. Payloads spread across multiple PR comments evade detection
  unless an aggregating layer is added.
- **Payload splitting** (Kang et al). Half the instruction in the PR
  title, half in the body. Each half is benign on its own.
- **Skeleton key / policy-puppetry attacks.** Semantic. Regex misses.
- **Single-space character spacing** ("i g n o r e p r e v i o u s"). The
  all-space variant is ambiguous because word boundaries cannot be
  recovered from spaced singletons. Intra-word separators (`i.g.n.o.r.e`,
  `i-g-n-o-r-e`) ARE handled.
- **ASCII art payloads** and **Caesar / ROT ciphers.** Documented bypass
  channels from arXiv:2308.06463. Not in the current normaliser.
- **Unicode TAG block** (U+E0000 to U+E007F). Invisible to humans,
  readable by tokenisers. Documented evasion path. Not yet detected.
- **Multimodal payloads.** Text embedded in images (PNG/JPG). Ward is
  text-only.
- **Indirect injection through retrieved content** (RAG vector stores,
  external web pages, runtime memory). Ward only scans repo-resident text
  and GitHub event metadata.

#### Operational caveats

- The `ward-allow-file` directive is honoured wherever it appears in a
  scanned doc file by default, so an attacker who edits a doc file in a
  PR could add a directive to suppress detection on that file. Close
  this in CI with `ward scan-local --suppression-base <base-ref>`,
  which only honours directives in files unchanged since the base ref.
  Directives in files the PR touched are ignored.
- Ward's tier 1 is a rule-based scanner, not a generative classifier.
  Novel zero-day injection techniques that do not match any rule pass
  through the regex tier silently until the rule pack is updated. Enable
  the LLM judge tier for a semantic second opinion.
- **The LLM judge tier classifies attacker-controlled text, so the judge
  itself can in principle be prompt-injected.** Ward mitigates this - the
  untrusted text is fenced with a one-time hash-derived delimiter the
  attacker cannot forge, every instruction lives in the trusted (cached)
  system prompt, and the model is constrained to a structured verdict
  rather than free text - but this is defence in depth, not a guarantee.
  Treat a judge verdict as advisory signal, not an unforgeable oracle,
  and keep the deterministic regex tier as your baseline. The judge is
  off by default and makes outbound calls to your configured LLM provider
  only when you enable it; Ward's core remains offline and zero-telemetry.

Ward is one defensive layer. It is not a complete solution. Defence in depth
still applies.

## Reporting a Vulnerability

If you find a security issue in Ward itself, please do not open a public
GitHub issue.

Email: `craig.mccart@outlook.com`
Subject line: `[WARD SECURITY]` followed by a short title.

Please include:
- A description of the issue.
- Steps to reproduce.
- Affected version.
- Any suggested remediation.

You will receive an acknowledgement within 72 hours. A coordinated disclosure
window of up to 90 days will be agreed before public release.

Ward will credit reporters in the release notes unless anonymity is
requested.

## Supported Versions

Ward is pre-1.0. Only the latest minor version receives security fixes.

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Telemetry

Ward sends no telemetry. It does not phone home, does not collect anonymous
usage statistics, and makes no outbound network requests except those you
explicitly trigger (for example `ward scan-pr`, which calls the GitHub API).
