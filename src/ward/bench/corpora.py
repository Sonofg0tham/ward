"""Descriptors for the bundled benchmark corpora.

A ``Corpus`` is a small piece of metadata plus a loader that yields
``(text, expect_detect)`` pairs. ``expect_detect`` is True when a row is
adversarial (we want Ward to flag it) and False when a row is benign
(we want Ward to leave it alone, so any detection there is a false
positive).
"""

from __future__ import annotations

import json
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from importlib import resources


class CorpusFit(str, Enum):
    """How Ward expects to perform on a given corpus."""

    IN_SCOPE = "in_scope"  # Ward should catch a high proportion
    CEILING_TEST = "ceiling_test"  # Out-of-scope by design; low score is the honest answer
    FALSE_POSITIVE = "false_positive"  # Benign-only set; any detection is a false positive


@dataclass(frozen=True)
class Corpus:
    """One benchmark corpus."""

    name: str
    description: str
    upstream_url: str
    license: str
    sample_file: str  # path within ``ward.bench.samples`` resources
    fit: CorpusFit
    # Surface to scan each row as. PR-body / commit-message are the closest
    # match for prose injection payloads; file_content avoids the suppression
    # directive footgun.
    surface: str = "pr_body"


def _iter_jsonl_path(path: object) -> Iterable[dict[str, object]]:
    """Yield each JSON object from a JSONL file-like path."""
    from pathlib import Path

    real = Path(str(path))
    for line in real.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        yield json.loads(line)


def _iter_jsonl_resource(resource_name: str) -> Iterable[dict[str, object]]:
    """Yield each JSON object from a bundled samples JSONL resource."""
    pkg = resources.files("ward.bench.samples")
    with resources.as_file(pkg / resource_name) as path:
        yield from _iter_jsonl_path(path)


def _cache_is_plausible(corpus: Corpus) -> bool:
    """Reject a cached corpus smaller than the bundled sample it replaces.

    The atomic download stops a *partial* write, but not a *complete but
    wrong* file - a stubbed fetch, a hand-edited cache, or an upstream that
    started serving a stub all produce a valid JSONL with too few rows.
    ``is_cached()`` said yes, bench scored it, and the report labelled the
    result "the full upstream corpora".

    This is not hypothetical: a one-row spikee cache silently turned a 55.5%
    full-corpus figure into 52.4%, which reads exactly like a detection
    regression. A corpus advertised as the full upstream set cannot contain
    fewer rows than the 50-row smoke sample shipped in the wheel.
    """
    from .download import cached_path

    path = cached_path(corpus.name)
    try:
        cached_rows = sum(1 for line in path.open(encoding="utf-8") if line.strip())
    except OSError:
        return False
    sample_rows = sum(1 for _ in _iter_jsonl_resource(corpus.sample_file))
    if cached_rows >= sample_rows:
        return True
    warnings.warn(
        f"Ignoring the cached corpus for {corpus.name}: it holds {cached_rows} row(s), "
        f"fewer than the {sample_rows}-row bundled sample, so it cannot be the full "
        f"upstream set. Falling back to the sample. Re-fetch with "
        f"`ward bench --download {corpus.name}`.",
        RuntimeWarning,
        stacklevel=2,
    )
    return False


def resolve_source(corpus: Corpus, *, use_cache: bool = True) -> str:
    """Return "full" or "sample" - whichever :func:`load_rows` will actually use.

    The single source of truth for the label. The runner used to recompute it
    from ``is_cached()`` alone, so when the plausibility guard rejected a stub
    cache and fell back to the bundled sample, the report still announced "the
    full upstream corpora" over 50 sample rows. That is the same
    quietly-wrong-number failure the guard was written to stop.
    """
    if not use_cache:
        return "sample"
    from .download import is_cached

    return "full" if is_cached(corpus.name) and _cache_is_plausible(corpus) else "sample"


def load_rows(corpus: Corpus, *, use_cache: bool = True) -> list[tuple[str, bool]]:
    """Return ``(text, expect_detect)`` pairs for a corpus.

    Uses a locally-cached full-corpus file (via ``ward bench --download``)
    when present and ``use_cache`` is true, else falls back to the bundled
    smoke sample.
    """
    source: Iterable[dict[str, object]]
    if use_cache:
        from .download import cached_path, is_cached

        if is_cached(corpus.name) and _cache_is_plausible(corpus):
            source = _iter_jsonl_path(cached_path(corpus.name))
        else:
            source = _iter_jsonl_resource(corpus.sample_file)
    else:
        source = _iter_jsonl_resource(corpus.sample_file)
    rows: list[tuple[str, bool]] = []
    for obj in source:
        text = str(obj.get("text", "")).strip()
        if not text:
            continue
        # deepset is the only labelled set; everything else is positive-only.
        if "label" in obj:
            expect_detect = bool(obj["label"])
        else:
            expect_detect = corpus.fit is not CorpusFit.FALSE_POSITIVE
        rows.append((text, expect_detect))
    return rows


CORPORA: tuple[Corpus, ...] = (
    Corpus(
        name="lakera_ignore_instructions",
        description="Real adversarial humans submitting short ignore-instruction phrasings.",
        upstream_url="https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
        license="MIT",
        sample_file="lakera_ignore_instructions.jsonl",
        fit=CorpusFit.IN_SCOPE,
    ),
    Corpus(
        name="deepset_prompt_injections",
        description="Balanced benign/injection set used to measure false positives.",
        upstream_url="https://huggingface.co/datasets/deepset/prompt-injections",
        license="Apache-2.0",
        sample_file="deepset_prompt_injections.jsonl",
        fit=CorpusFit.IN_SCOPE,
    ),
    Corpus(
        name="spikee_jailbreaks",
        description="Calibrated against the exact obfuscation techniques Ward defends.",
        upstream_url="https://github.com/WithSecureLabs/spikee",
        license="Apache-2.0",
        sample_file="spikee_jailbreaks.jsonl",
        fit=CorpusFit.IN_SCOPE,
    ),
    Corpus(
        name="advbench_harmful_behaviors",
        description="Bare harmful-intent strings; no injection phrasing. Published ceiling.",
        upstream_url="https://github.com/llm-attacks/llm-attacks",
        license="MIT",
        sample_file="advbench_harmful_behaviors.jsonl",
        fit=CorpusFit.CEILING_TEST,
    ),
)
