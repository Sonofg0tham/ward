"""Packaging invariants.

These check what actually ships. A wheel missing its rule pack would now
raise RulePackError for every user on every scan, and a wheel missing
py.typed silently degrades every SDK consumer's type checking to Any.
"""

from __future__ import annotations

import re
import tomllib
from importlib import resources
from pathlib import Path

import pytest

import ward
from ward.core.rules import load_rule_pack

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_rule_yamls_are_importable_package_data():
    """The bundled pack must resolve through importlib.resources, not the repo."""
    names = sorted(r.name for r in resources.files("ward.rules").iterdir())
    yamls = [n for n in names if n.endswith(".yaml")]
    assert len(yamls) >= 5, f"rule pack looks incomplete: {names}"
    assert load_rule_pack().rules


def test_bench_samples_ship_with_the_package():
    names = sorted(r.name for r in resources.files("ward.bench.samples").iterdir())
    jsonl = [n for n in names if n.endswith(".jsonl")]
    assert len(jsonl) == 4, f"expected 4 bundled corpora, got {jsonl}"


def test_py_typed_marker_is_present():
    """Without it, `from ward import Verdict` degrades to Any for consumers.

    That matters here more than usual: the documented SDK snippet branches on
    `report.verdict is not Verdict.PASS`, and an untyped package means a typo
    in that security-critical comparison type-checks clean.
    """
    marker = Path(ward.__file__).parent / "py.typed"
    assert marker.is_file(), "src/ward/py.typed is missing"


@pytest.mark.skipif(not (REPO_ROOT / "pyproject.toml").is_file(), reason="not a source checkout")
def test_declared_runtime_deps_are_actually_imported():
    """A dependency nobody imports is pure supply-chain surface.

    pydantic sat in this list unused, pulling itself and the pydantic-core
    Rust extension into every CI runner that installed Ward.
    """
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        dep.split(">")[0].split("[")[0].split("=")[0].strip().lower()
        for dep in data["project"]["dependencies"]
    }
    source = " ".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in (REPO_ROOT / "src" / "ward").rglob("*.py")
    )
    # The import name differs from the distribution name for some packages.
    module_for = {"pyyaml": "yaml"}
    for dist in sorted(declared):
        module = re.escape(module_for.get(dist, dist))
        # `import x`, `import x.y`, `from x import ...`, `from x.y import ...`
        pattern = rf"^\s*(?:import\s+{module}\b|from\s+{module}[.\s])"
        assert re.search(pattern, source, re.MULTILINE), (
            f"{dist} is declared as a runtime dependency but never imported. "
            "Drop it rather than shipping it to every consumer."
        )
