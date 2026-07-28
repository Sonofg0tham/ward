<!-- ward-allow-file: io.*, role.*, exf.*, tool.*, ait.*, obf.* -->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- What problem does this solve? For a new rule: what attack does it catch? -->

## Checklist

- [ ] `pytest` passes and coverage is still at or above 75%
- [ ] `ruff check src tests` and `ruff format --check src tests` pass
- [ ] `mypy src/ward` passes
- [ ] Added an entry to `CHANGELOG.md` under `## [Unreleased]`

### If this adds or changes a detection rule

- [ ] Added an attack fixture under `tests/fixtures/`
- [ ] Added a clean fixture under `tests/fixtures/clean/` proving no false positive
- [ ] Chose `surfaces:` deliberately rather than leaving the rule global
- [ ] Ran `ward bench --no-cache` and checked the false-positive rate is still 0.0%

<!--
CI reports what this change did to recall and FPR - as a PR comment for
branches on this repo, or in the bench-diff job log and artifact for forks.
If recall dropped or FPR rose, please explain the trade-off here.
-->
