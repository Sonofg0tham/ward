"""Audit: fixture/rule coverage matrix."""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import get_args

import yaml

from ward.core.engine import build_input, scan_inputs
from ward.core.models import Surface
from ward.core.rules import load_rule_pack

pack = load_rule_pack()
ALL_SURFACES = set(get_args(Surface))

named = defaultdict(list)
fired_in_attack = defaultdict(list)
attack_surfaces = Counter()
clean_surfaces = Counter()

for fp in sorted(Path("tests/fixtures").glob("*.yaml")):
    d = yaml.safe_load(fp.read_text(encoding="utf-8"))
    for r in d.get("expect_rule_ids") or []:
        named[r].append(fp.name)
    for item in d["inputs"]:
        attack_surfaces[item["surface"]] += 1
    inputs = [build_input(i["surface"], i["text"], location=fp.name) for i in d["inputs"]]
    rep = scan_inputs(inputs, pack, target=fp.name)
    for f in rep.findings:
        fired_in_attack[f.rule_id].append(fp.name)

for fp in sorted(Path("tests/fixtures/clean").glob("*.yaml")):
    d = yaml.safe_load(fp.read_text(encoding="utf-8"))
    for item in d["inputs"]:
        clean_surfaces[item["surface"]] += 1

print("=== RULES WITH NO ATTACK FIXTURE NAMING THEM ===")
no_named = [r.id for r in pack.rules if r.id not in named]
for rid in no_named:
    rule = pack.by_id(rid)
    incidental = sorted(set(fired_in_attack.get(rid, [])))
    print(f"  {rid:34s} {rule.severity.value:8s} incidental-hits={incidental}")
print(f"  -> {len(no_named)} of {len(pack.rules)} rules have no attack fixture")

print("\n=== RULES NEVER FIRING IN ANY ATTACK FIXTURE ===")
never = [r.id for r in pack.rules if r.id not in fired_in_attack]
for rid in never:
    print(f"  {rid:34s} {pack.by_id(rid).severity.value}")
print(f"  -> {len(never)}")

print("\n=== RULES WITH EMPTY surfaces: (apply to EVERY surface) ===")
for r in pack.rules:
    if not r.surfaces:
        print(f"  {r.id}")

print("\n=== SURFACE COVERAGE ===")
print("attack fixtures:")
for s in sorted(ALL_SURFACES):
    print(f"  {s:16s} attack={attack_surfaces.get(s,0):3d}  clean={clean_surfaces.get(s,0):3d}")
print("\nsurfaces with ZERO attack fixture input:", sorted(ALL_SURFACES - set(attack_surfaces)))
print("surfaces with ZERO clean fixture input:", sorted(ALL_SURFACES - set(clean_surfaces)))

print("\n=== SURFACES DECLARED BY RULES BUT NEVER IN A FIXTURE ===")
declared = set()
for r in pack.rules:
    declared |= set(r.surfaces)
print(sorted(declared - set(attack_surfaces)))
print("\nsurfaces no rule declares at all:", sorted(ALL_SURFACES - declared))
