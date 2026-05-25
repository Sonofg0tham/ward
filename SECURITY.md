<!-- ward-allow-file: io.*, role.*, exf.*, tool.*, ait.*, obf.* -->

# Security Policy

## Threat Model

Ward is a pattern-matching tool that screens the metadata an AI agent ingests
before that content reaches an LLM-based code reviewer, SAST agent, or IaC
scanner. It catches the attack class documented in OWASP ASI Top 10 (ASI01,
goal hijack via untrusted input) and in the March 2026 GitHub supply-chain
incidents.

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

- Novel zero-day injection techniques that do not match any rule. Ward is a
  rule-based scanner, not a generative classifier.
- Attacks embedded in non-text formats (images, PDFs, audio).
- Attacks on the LLM itself once context has been built. That is a prompt
  firewall's job (Lakera, LlamaFirewall). Ward sits earlier in the pipeline.
- Vulnerabilities in the code being reviewed. That is SAST's job. Ward does
  not compete with SAST.
- Agent-configuration tampering. That is BoltClaw's job. Ward protects agent
  input, BoltClaw protects agent configuration.

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
