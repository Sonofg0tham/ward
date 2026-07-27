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


def _pct(x: float | None) -> str:
    if x is None:
        return "n/a"
    return f"{x * 100:.1f}%"


def _delta_pp(new: float | None, base: float | None) -> str:
    """Delta in percentage points, or "n/a" when either side was not measured.

    Coercing a missing metric to 0 would invent a swing of the full magnitude
    of the other side and report it as a regression or an improvement.
    """
    if new is None or base is None:
        return "n/a"
    delta = (new - base) * 100
    if abs(delta) < 0.05:  # rounds to 0.0pp
        return "±0.0pp"
    return f"{delta:+.1f}pp"


def _metric(summary: dict[str, Any], key: str) -> float | None:
    value = summary.get(key)
    return None if value is None else float(value)


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
    base_recall = _metric(base_summary, "overall_recall_in_scope")
    new_recall = _metric(new_summary, "overall_recall_in_scope")
    base_fpr = _metric(base_summary, "overall_false_positive_rate_in_scope")
    new_fpr = _metric(new_summary, "overall_false_positive_rate_in_scope")

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
        # A corpus present in only one report was not measured in the other.
        # Coercing the absent side to 0 printed a fabricated full-magnitude
        # swing (-100.0pp) for what is really a rename or an addition.
        b = _metric(base_corpora.get(name, {}), "recall")
        n = _metric(new_corpora.get(name, {}), "recall")
        lines.append(f"| `{name}` | {_pct(b)} | {_pct(n)} | {_delta_pp(n, b)} |")
    lines.append("")

    # Gate each metric on its OWN measurability. A single combined guard meant
    # an unmeasured FPR silently swallowed the recall-regression warning - the
    # table would print a -40.0pp recall delta and then say "not comparable",
    # which is exactly the regression this workflow exists to shout about.
    verdicts: list[str] = []
    recall_known = base_recall is not None and new_recall is not None
    fpr_known = base_fpr is not None and new_fpr is not None

    if recall_known:
        assert base_recall is not None and new_recall is not None  # narrowing
        if new_recall < base_recall - 0.05:
            verdicts.append(
                f"⚠️ **Recall regression**: down {_delta_pp(new_recall, base_recall)} "
                "from the base. Investigate before merging."
            )
        elif new_recall > base_recall + 0.001:
            verdicts.append(f"✅ Recall improved by {_delta_pp(new_recall, base_recall)}.")
    else:
        verdicts.append("_Recall not comparable: zero in-scope rows scored in one report._")

    if fpr_known:
        assert base_fpr is not None and new_fpr is not None  # narrowing
        if new_fpr > base_fpr + 0.05:
            verdicts.append(
                f"⚠️ **False-positive regression**: up {_delta_pp(new_fpr, base_fpr)} "
                "from the base. Investigate before merging."
            )
    else:
        verdicts.append("_FPR not comparable: zero benign rows scored in one report._")

    if recall_known and fpr_known and len(verdicts) == 0:
        verdicts.append("_No change to headline detection numbers on the bundled samples._")
    lines.extend(verdicts)
    return "\n".join(lines)


def render_diff_from_paths(base_path: str | Path, new_path: str | Path) -> str:
    return render_diff(_load(base_path), _load(new_path))
