"""Descriptors for the bundled benchmark corpora.

A ``Corpus`` is a small piece of metadata plus a loader that yields
``(text, expect_detect)`` pairs. ``expect_detect`` is True when a row is
adversarial (we want Ward to flag it) and False when a row is benign
(we want Ward to leave it alone, so any detection there is a false
positive).
"""

from __future__ import annotations

import json
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


def load_rows(corpus: Corpus, *, use_cache: bool = True) -> list[tuple[str, bool]]:
    """Return ``(text, expect_detect)`` pairs for a corpus.

    Uses a locally-cached full-corpus file (via ``ward bench --download``)
    when present and ``use_cache`` is true, else falls back to the bundled
    smoke sample.
    """
    source: Iterable[dict[str, object]]
    if use_cache:
        from .download import cached_path, is_cached

        if is_cached(corpus.name):
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
