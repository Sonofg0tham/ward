"""Audit: every clean fixture stays clean; and which mechanism each attack fixture uses."""

from __future__ import annotations

from pathlib import Path

import yaml

from ward.core.engine import build_input, scan_inputs
from ward.core.rules import load_rule_pack

pack = load_rule_pack()

print("===== CLEAN FIXTURES =====")
for fp in sorted(Path("tests/fixtures/clean").glob("*.yaml")):
    data = yaml.safe_load(fp.read_text(encoding="utf-8"))
    dirty = []
    for item in data["inputs"]:
        inp = build_input(item["surface"], item["text"], location=fp.name)
        rep = scan_inputs([inp], pack, target=fp.name)
        for f in rep.findings:
            dirty.append((item["surface"], f.rule_id, f.severity.value, f.evidence[:70]))
    if dirty:
        print(f"\nFP {fp.name}:")
        for d in dirty:
            print(f"   {d}")
print("clean sweep done")

print("\n===== ATTACK FIXTURE MECHANISM =====")
# Which text form did the named rule actually match on?
for fp in sorted(Path("tests/fixtures").glob("*.yaml")):
    data = yaml.safe_load(fp.read_text(encoding="utf-8"))
    expected = set(data.get("expect_rule_ids") or [])
    if not expected:
        continue
    for item in data["inputs"]:
        inp = build_input(item["surface"], item["text"], location=fp.name)
        rep = scan_inputs([inp], pack, target=fp.name)
        for f in rep.findings:
            if f.rule_id not in expected:
                continue
            rule = pack.by_id(f.rule_id)
            if rule is None:
                continue
            where = []
            if any(p.search(inp.raw) for p in rule.patterns):
                where.append("raw")
            if any(p.search(inp.normalised) for p in rule.patterns):
                where.append("normalised")
            for i, d in enumerate(inp.decoded):
                if any(p.search(d) for p in rule.patterns):
                    where.append(f"decoded[{i}]")
            print(f"{fp.name:42s} {f.rule_id:28s} {item['surface']:15s} {where}")
