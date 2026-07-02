# Ward benchmark history

Every release commits its own numbers here so Ward's detection envelope
is auditable across versions. Two flavours per release:

- **`vX.Y.Z-smoke.{md,json}`** - scores against the 50-row samples
  bundled with the wheel. Deterministic, offline, quick. This is what
  `ward bench` produces without a network dependency and what the CI
  bench-diff job compares against on every PR.
- **`vX.Y.Z-full.{md,json}`** - scores against the full upstream
  corpora fetched by `ward bench --download <corpus>`. Real-world
  numbers. Longer tail of adversarial phrasings than the smoke sample
  can represent.

The full number is the credibility one; the smoke number is the
regression guard.

## Timeline

| Version | Smoke recall | Full recall | Smoke FPR | Full FPR | Notes |
|---------|--------------|-------------|-----------|----------|-------|
| v0.1.1  | 60.0% (inaugural) | not measured | 0.0% | - | First public benchmark |
| v0.1.2  | 75.2% | not measured | 0.0% | - | Rule expansion driven by inaugural misses |
| v0.1.3  | 75.2% | 53.5% | 0.0% | 0.0% | First full-corpus number; TAG-block + bench-diff hardening |
| v0.1.4  | 75.2% | 53.5% | 0.0% | 0.0% | Provenance-aware suppression (no detection change; hardening only) |

## How to reproduce

```bash
pip install "ward-scanner[bench-download]"
ward bench --download lakera_ignore_instructions \
           --download deepset_prompt_injections \
           --download spikee_jailbreaks \
           --download advbench_harmful_behaviors \
           --output my-bench.md
```

Cache lives at `~/.cache/ward/bench/` (Linux / macOS) or
`%LOCALAPPDATA%\ward\bench\` (Windows).
