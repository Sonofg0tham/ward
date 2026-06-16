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


def _iter_jsonl(resource_name: str) -> Iterable[dict[str, object]]:
    """Yield each JSON object from a bundled samples JSONL resource."""
    pkg = resources.files("ward.bench.samples")
    with resources.as_file(pkg / resource_name) as path:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def load_rows(corpus: Corpus) -> list[tuple[str, bool]]:
    """Return ``(text, expect_detect)`` pairs for a corpus.

    Bundled samples only at v0.1.x. Download-mode is on the v0.2 roadmap.
    """
    rows: list[tuple[str, bool]] = []
    for obj in _iter_jsonl(corpus.sample_file):
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
