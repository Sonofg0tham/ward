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
