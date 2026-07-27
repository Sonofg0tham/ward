<!-- ward-allow-file: io.*, role.*, exf.*, tool.*, ait.*, obf.* -->

# Changelog

All notable changes to Ward are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and Ward uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Ward is pre-1.0, so minor versions may carry breaking changes; those are
called out under **Changed** with a `BREAKING` marker.

Benchmark numbers quoted per release are the committed reports under
[`benchmark/`](benchmark/). "Smoke" is the bundled 50-row samples, "full"
is the downloaded upstream corpora.

## [Unreleased]

### Security

- **Rule packs now fail closed.** `load_rule_pack()` raises `RulePackError`
  instead of returning an empty pack when the `--rule-pack` directory is
  missing, is not a directory, contains no rule files, or otherwise
  resolves to zero rules. Previously a mistyped `--rule-pack` path scanned
  with no rules loaded and reported `PASS` with exit 0, silently disabling
  the gate in CI. The CLI surfaces this as exit 2.
- **The GitHub Action fails closed on scanner error.** `action/entrypoint.sh`
  exited 0 whenever `ward` returned an exit code outside 0/1/2 - including
  127 (not installed) and any interpreter crash - so a job where the scan
  never ran went green. It now emits a workflow error and exits non-zero.
- **PR references are validated before they reach the API URL.**
  `parse_pr_ref()` accepted path traversal in the owner and repo segments,
  so `ward scan-pr "a/../../evil#1"` resolved to
  `https://api.github.com/evil/pulls/1` with the caller's `GITHUB_TOKEN`
  attached. Owner and repo are now checked against GitHub's naming rules,
  and PR numbers must be positive.

### Added

- Duplicate rule ids are now rejected at load time. Two rules sharing an id
  made `ward explain <id>` and suppression directives resolve
  non-deterministically.
- `.yml` is accepted alongside `.yaml` in custom rule-pack directories. A
  directory of `.yml` rules previously loaded as an empty pack, silently.
- `tests/test_rules.py` - direct coverage for the rule loader, which had
  none. Fetch-path coverage for `github_api` via `httpx.MockTransport`.
- `CHANGELOG.md`, `CONTRIBUTING.md`, issue templates, and a pull request
  template.

### Fixed

- `ward update-rules` printed "Ward 0.1 ships rules inside the wheel" and
  promised community rule packs "in 0.2" while running as 0.2.3. It now
  reports the running version and points at `--rule-pack`.
- `SECURITY.md` listed Unicode TAG-block smuggling (U+E0000-U+E007F) under
  "not yet detected". It has been detected since v0.1.3 by
  `obf.unicode_tag`. Moved to the "what Ward catches" list.
- `SECURITY.md` supported-versions table still named 0.1.x as the supported
  line. Now 0.2.x.
- `.pre-commit-hooks.yaml` usage example pinned `rev: v0.1.0`.

## [0.2.3] - 2026-07-10

### Added

- Ward's own visual identity: logo, wordmark, social preview, and a
  project `brand.md` / `brand-theme.css`.

### Changed

- `action.yml` description shortened to fit the GitHub Marketplace limit.
- Dependabot now tracks the relocated root `action.yml` as well as
  `.github/workflows`.
- Action dependency bumps: `actions/checkout` 4 → 7, `actions/setup-python`
  5 → 6, `actions/upload-artifact` 4 → 7, `actions/download-artifact` 4 → 8,
  `softprops/action-gh-release` 2 → 3,
  `marocchino/sticky-pull-request-comment` 2 → 3.

### Removed

- Personal email address from `SECURITY.md` and `pyproject.toml`; security
  reports route through GitHub Security Advisories.

## [0.2.2] - 2026-07-10

Benchmark: 75.2% smoke recall, 53.5% full-corpus recall, 0.0% FPR.

### Added

- `ward bench --no-cache`, so a machine that has previously run
  `--download` cannot silently score the full corpora and label the report
  as smoke.
- Launch / portfolio write-up under `docs/`.

### Fixed

- Wheel build dropped a redundant `force-include` that broke packaging.
- Stale benign-row count in the README (271 → 343).

## [0.2.1] - 2026-07-02

### Added

- `ward lab review` - a real reviewer-agent harness. Runs each malicious PR
  twice, once with the reviewer ingesting raw metadata and once with Ward
  screening first. `NaiveReviewer` runs offline and deterministically;
  `AnthropicReviewer` needs the `[judge]` extra.

## [0.2.0] - 2026-07-02

### Added

- **Optional LLM judge tier.** Off by default, no LLM dependency in Ward's
  core. `ward judge` classifies a single string; `ward bench --judge`
  measures the judge's marginal recall lift over the regex tier. Engines:
  `mock` (offline, deterministic) and `anthropic` (needs the `[judge]`
  extra and `ANTHROPIC_API_KEY`).
- The judge fences attacker-controlled text with a one-time hash-derived
  delimiter, keeps every instruction in the trusted cached system prompt,
  and constrains the model to a structured verdict.

## [0.1.4] - 2026-07-02

### Added

- **Provenance-aware suppression.** `ward scan-local --suppression-base
  <ref>` only honours `ward-allow-file` directives in files unchanged since
  that ref, so a directive introduced by the PR under review cannot silence
  detection.

### Fixed

- Crash on Windows when scanning content containing characters outside the
  console code page.

## [0.1.3] - 2026-07-01

Benchmark: 75.2% smoke recall, 53.5% full-corpus recall (1,391 rows), 0.0% FPR.

### Added

- **Unicode TAG-block detection** (U+E0000-U+E007F) via `obf.unicode_tag`.
  TAG characters are invisible to humans but read by tokenisers; the
  normaliser folds ASCII-mapped TAG codepoints back so the smuggled
  instruction also fires its own rule.
- `ward bench --download` for the full upstream corpora, plus the
  `[bench-download]` extra for the parquet-formatted ones.
- Marketplace-ready `action.yml` at the repository root.
- Bench-as-guardrail in CI, with a per-PR bench-diff comment.

### Fixed

- mypy failing on CI where `pyarrow` is not installed.

## [0.1.2] - 2026-06-16

Benchmark: 75.2% in-scope recall (up from 60.0%), 0.0% FPR.

### Added

- `ward bench` - scores Ward against four bundled public adversarial
  corpora (Lakera ignore-instructions, deepset prompt-injections, Spikee
  jailbreaks, AdvBench harmful-behaviors). AdvBench is included as a
  deliberate ceiling test and scores 0% by design.

### Fixed

- Detection gaps surfaced by the first benchmark run.

## [0.1.1] - 2026-06-16

Inaugural benchmark: 60.0% in-scope recall, 0.0% FPR.

### Added

- `.wardignore` support - fnmatch-style path globs that suppress content
  scanning while still scanning filenames.
- Unicode TR39 confusable fold table, catching all-confusable-script tokens.
- Honest known-limitations section in `SECURITY.md`.

### Fixed

- **Suppression bypass:** `ward-allow-file` was honoured on the
  `code_comment` surface, so an attacker shipping a new source file could
  silence detection from its top comment. The directive is now honoured
  only on `file_content`.
- **Decode-evasion bypasses:** base64 76-character gate, URL-encoded,
  HTML-entity and quoted-printable payloads, and recursive decoding.
- Replaced a fabricated attack narrative in the README with the verified
  2026 incidents.

## [0.1.0] - 2026-05-25

Initial release.

### Added

- Six detector categories: instruction override, role manipulation,
  obfuscation, tool-call injection, exfiltration, AI-tool-specific quirks.
- CLI: `scan-stdin`, `scan-branch`, `scan-commit`, `scan-local`, `scan-pr`,
  `explain`, `selftest`, `attack-demo`, `version`.
- Reporters: pretty, JSON, SARIF.
- Evasion-resistant normalisation: leetspeak, intra-word separators,
  repeated letters, zero-width unicode, NFKC, base64 and hex decoding,
  identifier delimiters.
- `ward lab attack` adversarial lab harness.
- Composite GitHub Action and pre-commit framework hooks.
- Dependabot configuration.

[Unreleased]: https://github.com/sonofg0tham/ward/compare/v0.2.3...HEAD
[0.2.3]: https://github.com/sonofg0tham/ward/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/sonofg0tham/ward/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/sonofg0tham/ward/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/sonofg0tham/ward/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/sonofg0tham/ward/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/sonofg0tham/ward/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/sonofg0tham/ward/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/sonofg0tham/ward/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/sonofg0tham/ward/releases/tag/v0.1.0
