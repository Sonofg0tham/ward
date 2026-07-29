import sys, json
sys.path.insert(0, "src")
from ward.core.engine import build_input, scan_inputs
from ward.core.rules import load_rule_pack

PACK = load_rule_pack()

def scan(text, surface="pr_body"):
    inp = build_input(surface, text)
    rep = scan_inputs([inp], PACK, target="audit")
    return rep

def brief(text, surface="pr_body"):
    rep = scan(text, surface)
    return [(f.rule_id, f.severity.value) for f in rep.findings], rep.verdict.value

if __name__ == "__main__":
    data = sys.stdin.read()
    surface = sys.argv[1] if len(sys.argv) > 1 else "pr_body"
    print(brief(data, surface))
