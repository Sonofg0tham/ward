"""Audit: every attack fixture -> does its NAMED rule actually fire?"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

from ward.core.engine import build_input, scan_inputs
from ward.core.models import Verdict
from ward.core.rules import load_rule_pack
from ward.core.verdict import aggregate

FIX = Path("tests/fixtures")
pack = load_rule_pack()

problems = []
for fp in sorted(FIX.glob("*.yaml")):
    data = yaml.safe_load(fp.read_text(encoding="utf-8"))
    inputs = [build_input(i["surface"], i["text"], location=fp.name) for i in data["inputs"]]
    report = scan_inputs(inputs, pack, target=fp.name)
    fired = {f.rule_id for f in report.findings}
    expected = data.get("expect_rule_ids") or []
    exp_verdict = Verdict(data["expect_verdict"])
    missing = [r for r in expected if r not in fired]
    hit = [r for r in expected if r in fired]

    # would the verdict hold on the NAMED rules alone?
    only_named = tuple(f for f in report.findings if f.rule_id in set(expected))
    named_report = aggregate(only_named, target=fp.name)
    sevs = {r: pack.by_id(r).severity.value if pack.by_id(r) else "NO-SUCH-RULE" for r in expected}
    fired_sev = sorted({(f.rule_id, f.severity.value) for f in report.findings})

    status = []
    if missing:
        status.append(f"MISSING={missing}")
    if not hit:
        status.append("NO NAMED RULE FIRED")
    elif named_report.verdict is not exp_verdict:
        status.append(
            f"NAMED-ONLY verdict={named_report.verdict.value} != declared {exp_verdict.value}"
        )
    for r in expected:
        if pack.by_id(r) is None:
            status.append(f"RULE ID DOES NOT EXIST: {r}")

    if status:
        problems.append(fp.name)
        print(f"\n### {fp.name}: {' | '.join(status)}")
        print(f"    declared: verdict={exp_verdict.value} rules={expected} sevs={sevs}")
        print(f"    actual verdict={report.verdict.value}")
        print(f"    all fired: {fired_sev}")

print(f"\n\n=== {len(problems)} problem fixtures of {len(list(FIX.glob('*.yaml')))} ===")
print(problems)
