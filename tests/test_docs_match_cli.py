"""The README must describe every command Ward actually ships.

Four commands - selftest, attack-demo, update-rules, bench-diff - existed for
several releases without ever being mentioned in the README. Nobody noticed,
because nothing checked. A CLI command that is not documented may as well not
exist, and `selftest` in particular is the fastest way for a user to confirm
an install or a custom rule pack works.
"""

from __future__ import annotations

import pathlib
import re

from ward.cli import app

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"


def _command_names() -> set[str]:
    names = {c.name or c.callback.__name__.replace("_", "-") for c in app.registered_commands}
    names |= {g.name for g in app.registered_groups if g.name}
    return names


def _is_documented(name: str, text: str) -> bool:
    """Whole-command match, not a substring.

    A plain ``f"ward {name}" in text`` check is vacuous here: "ward bench" is
    a substring of "ward bench-diff", so deleting the entire bench section
    would still pass as long as bench-diff survived. Mutation-testing this
    file is what surfaced it - the first version of this test did not fail
    when the command it checked was renamed.
    """
    return re.search(rf"\bward {re.escape(name)}(?![\w-])", text) is not None


def test_readme_documents_every_command() -> None:
    text = README.read_text(encoding="utf-8")
    undocumented = sorted(n for n in _command_names() if not _is_documented(n, text))
    assert not undocumented, (
        f"commands missing from README.md: {undocumented}. "
        "Add them to the 'Other commands' section - an undocumented command "
        "is one nobody will run."
    )


def test_readme_does_not_advertise_commands_that_do_not_exist() -> None:
    """The other direction: a renamed command must not linger in the docs.

    Catches the copy-paste failure where a command is renamed in cli.py and
    the README keeps advertising the old name, which then fails for every
    reader who copies it.
    """
    text = README.read_text(encoding="utf-8")
    real = _command_names()
    advertised: set[str] = set()
    # Only look inside bash fences, so prose like "ward scans the repo" is safe.
    for block in re.findall(r"```bash\n(.*?)```", text, re.S):
        for line in block.splitlines():
            match = re.match(r"\s*ward\s+([a-z][a-z0-9-]*)", line)
            if match:
                advertised.add(match.group(1))
    stale = sorted(advertised - real)
    assert not stale, f"README advertises commands that do not exist: {stale}"


def test_explain_knows_every_rule_id_ward_can_emit() -> None:
    """`ward explain <id>` must work for any id in Ward's own report.

    Most rules come from YAML and are found automatically. Four did not:
    obf.mixed_script, obf.unicode_tag and the two scan-integrity ids are
    constructed in code, so they were absent from the explain table and
    `ward explain obf.mixed_script` said "Unknown rule id" for a rule
    SECURITY.md names by id.

    The emitted ids are collected from the source rather than hand-listed,
    so adding a new code-defined finding without documenting it fails here.
    """
    import re as _re

    from ward.cli import _heuristic_rule_doc
    from ward.core.rules import load_rule_pack

    known = {rule.id for rule in load_rule_pack().rules}

    src_root = pathlib.Path(__file__).resolve().parents[1] / "src" / "ward"
    emitted: set[str] = set()
    for path in src_root.rglob("*.py"):
        for match in _re.finditer(
            r'rule_id="([a-z_]+\.[a-z_]+)"', path.read_text(encoding="utf-8")
        ):
            emitted.add(match.group(1))

    assert emitted, "no rule_id= literals found; the scan is not working"
    undocumented = sorted(
        rid for rid in emitted if rid not in known and _heuristic_rule_doc(rid, object) is None
    )
    assert not undocumented, (
        f"`ward explain` does not know these ids, which Ward emits: {undocumented}. "
        "Add them to _heuristic_rule_doc - an id in a report that explain cannot "
        "resolve sends the reader nowhere."
    )
