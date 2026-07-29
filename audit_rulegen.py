"""Audit: can every rule id be made to fire, on every surface it declares?

Generates a string matching each rule pattern by inverting the parsed regex,
verifies it with re.search, then feeds it through the real engine on each
declared surface and checks the rule id appears in the findings.
"""

from __future__ import annotations

import random
import re
import re._parser as sre_parse  # type: ignore[import-not-found]
import string
import sys

from ward.core.engine import build_input, scan_inputs
from ward.core.rules import load_rule_pack

SAFE = string.ascii_lowercase + " "
random.seed(0)


def gen(node, groups):  # noqa: C901
    out = []
    for op, av in node:
        o = str(op)
        if o == "LITERAL":
            out.append(chr(av))
        elif o == "NOT_LITERAL":
            c = random.choice(SAFE)
            while ord(c) == av:
                c = random.choice(SAFE)
            out.append(c)
        elif o == "ANY":
            out.append(random.choice(string.ascii_lowercase))
        elif o == "IN":
            out.append(gen_in(av))
        elif o == "MAX_REPEAT" or o == "MIN_REPEAT":
            lo, hi, sub = av
            hi = min(hi, lo + 2) if hi < 4294967295 else lo + 1
            n = random.randint(lo, max(lo, hi))
            for _ in range(n):
                out.append(gen(sub, groups))
        elif o == "SUBPATTERN":
            gid, _, _, sub = av
            s = gen(sub, groups)
            if gid:
                groups[gid] = s
            out.append(s)
        elif o == "BRANCH":
            _, branches = av
            out.append(gen(random.choice(branches), groups))
        elif o == "AT":
            pass
        elif o == "ASSERT":
            # positive lookahead/behind: emit its content (approximation)
            out.append(gen(av[1], groups))
        elif o == "ASSERT_NOT":
            pass
        elif o == "GROUPREF":
            out.append(groups.get(av, ""))
        elif o == "ATOMIC_GROUP":
            out.append(gen(av, groups))
        elif o == "CATEGORY":
            out.append(gen_cat(av))
        elif o == "NEGATE":
            pass
        else:
            raise NotImplementedError(f"op {o} av {av!r}")
    return "".join(out)


def gen_cat(av):
    c = str(av)
    return {
        "CATEGORY_DIGIT": random.choice(string.digits),
        "CATEGORY_NOT_DIGIT": random.choice(string.ascii_lowercase),
        "CATEGORY_SPACE": " ",
        "CATEGORY_NOT_SPACE": random.choice(string.ascii_lowercase),
        "CATEGORY_WORD": random.choice(string.ascii_lowercase),
        "CATEGORY_NOT_WORD": random.choice(" .,-"),
    }.get(c, "x")


def gen_in(items):
    neg = any(str(op) == "NEGATE" for op, _ in items)
    if neg:
        pos = set()
        for op, av in items:
            if str(op) == "LITERAL":
                pos.add(chr(av))
            elif str(op) == "RANGE":
                pos.update(chr(i) for i in range(av[0], av[1] + 1))
        for _ in range(200):
            c = random.choice(SAFE)
            if c not in pos:
                return c
        return "§"
    choices = []
    for op, av in items:
        o = str(op)
        if o == "LITERAL":
            choices.append(chr(av))
        elif o == "RANGE":
            lo, hi = av
            choices.append(chr(random.randint(lo, min(hi, lo + 40))))
        elif o == "CATEGORY":
            choices.append(gen_cat(av))
    return random.choice(choices) if choices else "x"


def make_match(pat: re.Pattern[str], tries: int = 4000) -> str | None:
    parsed = sre_parse.parse(pat.pattern, pat.flags)
    for _ in range(tries):
        try:
            s = gen(parsed, {})
        except (NotImplementedError, IndexError, ValueError):
            return None
        if pat.search(s):
            return s
    return None


pack = load_rule_pack()
unfirable = []
partial = []
nogen = []
for rule in pack.rules:
    fired_on = set()
    used = {}
    for surf in sorted(rule.surfaces):
        for pi, pat in enumerate(rule.patterns):
            s = make_match(pat)
            if s is None:
                continue
            try:
                inp = build_input(surf, s, location="gen")
            except ValueError:
                continue
            rep = scan_inputs([inp], pack, target="gen")
            if rule.id in {f.rule_id for f in rep.findings}:
                fired_on.add(surf)
                used[surf] = (pi, s)
                break
    missing = sorted(set(rule.surfaces) - fired_on)
    if not fired_on:
        gens = [make_match(p) for p in rule.patterns]
        if all(g is None for g in gens):
            nogen.append(rule.id)
            print(f"NO-GEN  {rule.id} ({rule.severity.value}) - generator failed on all patterns")
        else:
            unfirable.append(rule.id)
            print(f"DEAD    {rule.id} ({rule.severity.value}) surfaces={sorted(rule.surfaces)}")
            for g in gens:
                print(f"        gen={g!r}")
    elif missing:
        partial.append((rule.id, missing))
        print(f"PARTIAL {rule.id}: fired on {sorted(fired_on)}, NOT on {missing}")

print(f"\ntotal rules={len(pack.rules)} dead={len(unfirable)} partial={len(partial)} nogen={len(nogen)}")
print("NOGEN:", nogen)
