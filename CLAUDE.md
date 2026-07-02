# Ward

Pre-agent metadata scanner. Catches prompt injection in branch names, commits, PR titles/bodies and filenames before they reach an AI code reviewer. Python 3.11+ Typer CLI (`ward`) plus a composite GitHub Action.

## Key files

- `src/ward/cli.py` - CLI entry. Commands: scan-stdin, scan-branch, scan-commit, scan-local, scan-pr, explain, selftest, attack-demo, update-rules, lab, bench, bench-diff, judge.
- `src/ward/core/` - engine, rules loader, normalise (homoglyph/unicode/TAG-block/evasion), verdict, github_api, wardignore.
- `src/ward/detectors/` - one module per attack category (instruction_override, obfuscation, exfiltration, etc.).
- `src/ward/rules/*.yaml` - bundled rule packs.
- `src/ward/reporters/` - pretty, json, sarif output.
- `src/ward/bench/` - benchmark harness (corpora, runner, report, compare, download) + bundled samples.
- `src/ward/judge/` - optional LLM judge tier (base, mock, anthropic_judge, prompt). Off by default; needs the [judge] extra.
- `action.yml` - the GitHub Action at repo root (inputs: pr, fail-on, format, upload-sarif...). entrypoint under `action/`.
- `tests/fixtures/` - numbered YAML attack fixtures; `tests/fixtures/clean/` - false-positive fixtures that must NOT trigger.

## Run / test

```
pip install -e ".[dev]"
pytest                  # coverage must stay >= 75%
ruff check . && ruff format .
mypy                    # strict mode, covers src/ward
```

## Conventions

- Ruff: line-length 100, py311 target. Mypy strict.
- RUF001-003 are deliberately ignored in homoglyph-handling files (normalise, obfuscation, demo, selftest and their tests). Never "fix" Cyrillic or ambiguous unicode there - it is the test payload.
- `class Foo(str, Enum)` is intentional; do not convert to StrEnum (changes str() output).
- New detection rules need both an attack fixture and, where relevant, a clean fixture proving no false positive.
