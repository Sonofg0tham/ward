"""Compare two benchmark JSON reports and render the diff as Markdown.

Used by CI to comment on every PR with the recall / FPR delta versus the
base branch. Makes silent regressions on detection numbers visible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        loaded = json.load(fh)
    return loaded if isinstance(loaded, dict) else {}


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _delta_pp(new: float, base: float) -> str:
    delta = (new - base) * 100
    if abs(delta) < 0.05:  # rounds to 0.0pp
        return "±0.0pp"
    return f"{delta:+.1f}pp"


def render_diff(base_report: dict[str, Any], new_report: dict[str, Any]) -> str:
    """Return a self-contained Markdown block summarising base vs new bench."""
    lines: list[str] = []
    lines.append("<!-- ward-bench-diff -->")
    lines.append("## Ward bench diff")
    lines.append("")
    lines.append(
        f"Base version: `{base_report.get('version', '?')}`  |  "
        f"PR version: `{new_report.get('version', '?')}`"
    )
    lines.append("")

    base_summary = base_report.get("summary", {})
    new_summary = new_report.get("summary", {})
    base_recall = float(base_summary.get("overall_recall_in_scope", 0))
    new_recall = float(new_summary.get("overall_recall_in_scope", 0))
    base_fpr = float(base_summary.get("overall_false_positive_rate_in_scope", 0))
    new_fpr = float(new_summary.get("overall_false_positive_rate_in_scope", 0))

    lines.append("### Headline")
    lines.append("")
    lines.append("| Metric | Base | PR | Delta |")
    lines.append("|--------|------|----|-------|")
    lines.append(
        f"| In-scope recall | {_pct(base_recall)} | {_pct(new_recall)} | "
        f"{_delta_pp(new_recall, base_recall)} |"
    )
    lines.append(
        f"| In-scope FPR | {_pct(base_fpr)} | {_pct(new_fpr)} | {_delta_pp(new_fpr, base_fpr)} |"
    )
    lines.append("")

    base_corpora = {c["name"]: c for c in base_report.get("corpora", []) if isinstance(c, dict)}
    new_corpora = {c["name"]: c for c in new_report.get("corpora", []) if isinstance(c, dict)}

    lines.append("### Per-corpus recall")
    lines.append("")
    lines.append("| Corpus | Base | PR | Delta |")
    lines.append("|--------|------|----|-------|")
    all_names = sorted(set(base_corpora) | set(new_corpora))
    for name in all_names:
        b = float(base_corpora.get(name, {}).get("recall", 0))
        n = float(new_corpora.get(name, {}).get("recall", 0))
        lines.append(f"| `{name}` | {_pct(b)} | {_pct(n)} | {_delta_pp(n, b)} |")
    lines.append("")

    if abs(new_recall - base_recall) < 0.001 and abs(new_fpr - base_fpr) < 0.001:
        lines.append("_No change to headline detection numbers on the bundled samples._")
    elif new_recall < base_recall - 0.05:
        lines.append(
            f"⚠️ **Recall regression**: down {_delta_pp(new_recall, base_recall)} from the base. "
            "Investigate before merging."
        )
    elif new_fpr > base_fpr + 0.05:
        lines.append(
            f"⚠️ **False-positive regression**: up {_delta_pp(new_fpr, base_fpr)} from the base. "
            "Investigate before merging."
        )
    elif new_recall > base_recall:
        lines.append(f"✅ Recall improved by {_delta_pp(new_recall, base_recall)}.")
    return "\n".join(lines)


def render_diff_from_paths(base_path: str | Path, new_path: str | Path) -> str:
    return render_diff(_load(base_path), _load(new_path))
