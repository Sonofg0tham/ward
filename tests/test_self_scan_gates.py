"""Ward's self-scan has to gate on something, or nobody reads it.

The self-scan step in CI carries `continue-on-error: true`, and it is not
going away: Ward's own commit messages describe the attacks it catches and its
own fixture FILENAMES are payloads, so `scan-local` on this repository will
always exit 2. `.wardignore` cannot help - it suppresses file CONTENT, not
commit metadata or names.

The cost of that showed up in round eighteen. A committed PNG was producing
`obf.mixed_script` and `obf.bidi_override` at HIGH on `assets/social-preview.png`,
which meant any repository with a logo could not commit - and Ward's own CI
had been reporting it green for a round, because `continue-on-error` swallowed
it. A step that cannot fail is a step that tells you nothing.

So gate on the part that CAN pass. Every legitimate self-finding lands on
`commit_message` or `file_name`; `.wardignore` covers Ward's whole source
tree and its fixtures, so a finding on `file_content` or `code_comment` means
either a new false positive or a hole in the ignore file. The PNG regression
was `obf.bidi_override` on `file_content` at `assets/social-preview.png` -
this test would have been red the moment it appeared.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# The surfaces .wardignore and ward-allow-file are able to suppress. Findings
# on commit_message, file_name, branch_name and the other identifier surfaces
# are Ward's own history and fixture names and are expected.
SUPPRESSIBLE_SURFACES = {"file_content", "code_comment"}


@pytest.fixture(scope="module")
def self_scan() -> dict:
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout, so there is no repository to self-scan")
    proc = subprocess.run(
        [sys.executable, "-m", "ward.cli", "scan-local", "--repo", str(ROOT), "--format", "json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=ROOT,
    )
    # Exit 2 is expected and is not what this module is testing. A crash is:
    # no JSON on stdout means the scan died rather than reported.
    assert proc.stdout.strip(), (
        f"scan-local produced no JSON (exit {proc.returncode}). stderr:\n{proc.stderr[-2000:]}"
    )
    return json.loads(proc.stdout)


def test_self_scan_reports_nothing_on_suppressible_surfaces(self_scan: dict) -> None:
    """The check `continue-on-error` was hiding.

    A hit here is one of two things and both need a human: a false positive
    Ward is producing on ordinary repository content, or a gap in
    `.wardignore`. Neither should reach a release quietly.
    """
    offenders = [
        f"{f['rule_id']} ({f['severity']}) on {f['surface']} at {f['location']}"
        for f in self_scan["findings"]
        # scan_integrity findings are the scan describing its own coverage -
        # "this file's bytes decoded as nothing, so the hidden-character rules
        # did not run on it". That is the honest report on a committed logo,
        # not a false positive, and .wardignore is not meant to hide it.
        if f["surface"] in SUPPRESSIBLE_SURFACES and f["category"] != "scan_integrity"
    ]
    assert not offenders, (
        "scan-local reported findings on content surfaces that .wardignore covers:\n  "
        + "\n  ".join(offenders)
        + "\nEither Ward has a new false positive on ordinary repository content, or "
        ".wardignore has a hole. This is the check CI's `continue-on-error` was hiding."
    )


def test_self_scan_still_finds_its_own_history(self_scan: dict) -> None:
    """The control. Without it the test above passes on an empty scan.

    If `scan-local` ever stops reading commit messages, the assertion above
    goes green by finding nothing at all - which is the failure mode this
    whole branch keeps re-learning.
    """
    surfaces = {f["surface"] for f in self_scan["findings"]}
    assert surfaces, "scan-local found nothing at all in a repo whose history describes attacks"
    assert surfaces - SUPPRESSIBLE_SURFACES, (
        f"scan-local only reported on {sorted(surfaces)}; it is no longer scanning "
        "commit metadata, so the guard above proves nothing"
    )


def test_no_binary_asset_produces_an_obfuscation_finding(self_scan: dict) -> None:
    """Named separately because this is the one that actually shipped.

    `assets/social-preview.png` re-read as UTF-16 decodes to dense CJK, every
    codepoint of which is printable, so 68,030 of its 78,065 characters
    survived the readability filter and the character-level rules fired on
    decode noise.
    """
    obf = [
        f"{f['rule_id']} on {f['location']}"
        for f in self_scan["findings"]
        if f["rule_id"].startswith("obf.")
    ]
    assert not obf, "obfuscation findings on Ward's own tracked files:\n  " + "\n  ".join(obf)
