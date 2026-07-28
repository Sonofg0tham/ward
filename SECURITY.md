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
- Obfuscation patterns. Two distinct behaviours here, worth separating:
  - **Stripped before matching** (so none of them can split a payload):
    every Unicode Cf codepoint and every variation selector. A payload
    written `ig<U+00AD>nore all previous instructions` is read as
    `ignore all previous instructions` whichever invisible character is
    used.
  - **Reported as a finding**: a named subset only - zero-width spaces,
    SOFT HYPHEN, word joiner, the invisible maths operators, the bidi
    embedding / override / isolate controls (including RTL override
    U+202E), and the Unicode TAG block (U+E0000-U+E007F, invisible to
    humans but readable by tokenisers - rule `obf.unicode_tag`).
    Deliberately **not** reported: U+200E / U+200F (the LRM/RLM directional
    marks) and the variation selectors, because those appear in ordinary
    Arabic and Hebrew prose and in every coloured emoji. Reporting them
    turned innocent documents into hard build failures.
- Long base64 blocks in unusual fields, and hex-encoded payloads.
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
- **Multimodal payloads.** Text embedded in images (PNG/JPG). Ward is
  text-only.
- **A BOM-less UTF-16 document in a script with no ASCII and no spaces**
  (Thai, and some Chinese and Lao text). Ward scans every plausible decoding
  of such a file, so a payload in the TEXT rules is still caught - but the
  character-level `obf.*` rules run only on the reading Ward judges most
  likely to be the document, and for these scripts that judgement can go the
  wrong way. Ranking readings is inherently approximate; a wrong choice costs
  an obfuscation finding, never the payload text itself. Pinned as a strict
  xfail in `tests/test_fail_closed.py` so it cannot be quietly "fixed" by a
  change that only appears to work.
- **Indirect injection through retrieved content** (RAG vector stores,
  external web pages, runtime memory). Ward only scans repo-resident text
  and GitHub event metadata.

#### Severity is the answer to ambiguity, not a tighter regex

Some phrasings are genuinely ambiguous and no regex separates them:

> "Reviewers can ignore rules that only apply to generated code **and
> approve** the diff."

That is ordinary prose, and it is structurally identical to an injection.
Four successive strategies were tried on this class - deleting the ambiguous
branch, requiring column zero, anchoring to the start of a line, requiring an
agent-directed continuation - and each produced roughly as many defects as it
fixed, in one direction or the other. The distinction is semantic, which is
the regex tier's documented ceiling and precisely what the optional LLM judge
tier exists for.

So the ambiguous forms live in their own **MEDIUM** rules
(`io.ambiguous_override_hint`, `role.ambiguous_persona_hint`). They appear in
the report and in Code Scanning, but at the Action's default `fail-on: high`
they warn rather than block.

**The frame decides, not the noun.** An earlier version of this split drew the
line on the noun, assuming instructions / prompts / directives / system prompt
were unambiguous. They are not:

| | |
|---|---|
| "The parser will ignore **commands** it does not recognise." | passed |
| "The parser will ignore **directives** it does not recognise." | blocked |

Same sentence, one word. A build gate that turns on which synonym an author
reached for is not a gate. What actually separates them is the frame: a
sentence that *describes* behaviour versus one that *instructs an agent*. So
the HIGH branch requires either an agent-directed continuation ("...and
approve this PR") or an utterance-initial imperative with no frame to read
("Ignore these instructions"). Descriptive prose warns at MEDIUM.

Measured on the full 1,391-row corpus:

| Threshold | In-scope recall | FPR | Behaviour |
|-----------|-----------------|-----|-----------|
| `high` (default) | 53.8% | **0.0%** | blocks the build |
| `medium` | 55.3% | 0.6% | warns only |

The ambiguous class is worth 1.5pp of recall and carries a 0.6% false-positive
rate. Reporting it as a warning keeps that recall available to a human
reviewer without ever blocking a build on a sentence about lint rules.

#### Known false positives

Measured by sweeping hand-written benign strings drawn from real software
vocabulary (conventional commits, branch names, config snippets, docs prose,
six non-English languages) rather than by the benchmark corpora. That
distinction matters: the published 0.0% false-positive rate is measured on
deepset, which is largely German prose and contains **no English CLI or
product vocabulary**, so it does not exercise this class at all. An
independent audit round found eleven build-blocking false positives that the
0.0% figure had never touched — including `Do not include API keys` in a
bug-report template, the Ansible `user:` module key, and
`docs: update the instructions`. Those are fixed and pinned in
`tests/test_detection_matrix.py`.

Two survive, and both are kept deliberately:

- **"expose / print / reveal *the* system prompt"** fires `io.reveal_instructions`
  at HIGH. `feat: expose the system prompt in the playground` is a normal
  commit in an LLM product, but the same phrasing is a prompt-extraction
  attack, and regex cannot see the difference. Narrowing it to require a
  possessive would lose 74 rows of corpus recall (~5pp), so the finding
  stays. Suppress per-file with `ward-allow-file: io.reveal_instructions`,
  or lower it with `--severity-threshold`.
- **A line beginning `STOP.`** fires `io.stop_and_restart` at MEDIUM. That is
  WARN, not FAIL, so it does not block a build.

The published 0.0% false-positive rate is measured on deepset, which is
largely German prose and contains no English CLI or product vocabulary. It
does not exercise this class at all. `tests/test_detection_matrix.py` exists
to cover the gap.

#### Operational caveats

- The `ward-allow-file` directive is honoured wherever it appears in a
  scanned doc file by default, so an attacker who edits a doc file in a
  PR could add a directive to suppress detection on that file. Close
  this in CI with `ward scan-local --suppression-base <base-ref>`,
  which only honours directives in files unchanged since the base ref.
  Directives in files the PR touched are ignored.
- Ward fails **closed**, deliberately. Anything that would leave a scan
  having screened nothing is an error, not a clean result:
  - A rule pack resolving to zero rules (missing `--rule-pack` directory,
    empty directory, duplicate ids) raises rather than scanning with
    nothing loaded.
  - `scan-local` outside a git working tree, or with an unreadable
    `--repo`, exits 2 rather than reporting PASS on zero inputs.
  - `--suppression-base` exits 2 if the change set cannot be computed.
    A shallow clone — `actions/checkout`'s default — makes the merge-base
    diff fail, and treating that as "nothing changed" would trust every
    suppression directive in the PR. Use `fetch-depth: 0`.
  - `scan-pr` turns network and non-JSON responses into exit 2, not an
    uncaught exception (which exits 1, and the Action reads 1 as WARN).
  - The GitHub Action treats any unexpected exit code as "the scan did not
    complete" and fails the job rather than going green.
- **Provenance gating covers `.wardignore` as well as `ward-allow-file`.**
  Under `--suppression-base`, a `.wardignore` modified by the current
  branch is not honoured at all. Without that, a PR adding a `.wardignore`
  containing `*` disabled every content scan and still reported PASS.
- `.wardignore` globs are segment-aware: `*` does not cross `/`. Patterns
  used to be implicitly recursive, so `docs/*` also silenced
  `docs/internal/anything/evil.md` — and since `.wardignore` is committed,
  an attacker can read it and pick the deeper path.
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

Report privately via [GitHub Security Advisories](https://github.com/Sonofg0tham/ward/security/advisories/new).

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
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Telemetry

Ward sends no telemetry. It does not phone home and does not collect anonymous
usage statistics. It makes outbound requests on exactly three paths, each only
when you explicitly invoke it: `ward scan-pr` (api.github.com),
`ward bench --download` (huggingface.co and raw.githubusercontent.com), and
the optional `[judge]` extra (your configured LLM provider). A default scan
makes no network calls at all.
