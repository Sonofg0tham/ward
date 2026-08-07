"""The composite action must never report a green job for a scan that failed.

These drive action/entrypoint.sh with a stub `ward` on PATH, so every exit
code and report shape is exercised without touching the GitHub API.
"""

from __future__ import annotations

import os
import pathlib
import shutil
import stat
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRYPOINT = REPO_ROOT / "action" / "entrypoint.sh"

BASH = shutil.which("bash") or shutil.which("sh")
pytestmark = pytest.mark.skipif(BASH is None, reason="no POSIX shell available")


def _run(tmp_path: pathlib.Path, *, exit_code: int, report: str) -> tuple[int, str]:
    """Run the entrypoint against a stub ward. Returns (job exit code, verdict)."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "ward"
    stub.write_text(
        f"#!/usr/bin/env bash\nprintf '%s' {report!r}\nexit {exit_code}\n",
        encoding="utf-8",
        newline="\n",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "WARD_PR_INPUT": "1",
        "WARD_REPO_INPUT": "acme/widget",
        "WARD_FORMAT": "json",
        "WARD_FAIL_ON": "high",
        "WARD_THRESHOLD": "low",
        "WARD_RULE_PACK": "",
        "WARD_OUTPUT": "",
        "GITHUB_REPOSITORY": "acme/widget",
        "GITHUB_OUTPUT": str(tmp_path / "gh_output"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
    }
    proc = subprocess.run(
        [BASH, str(ENTRYPOINT)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        errors="replace",
    )
    outputs = (tmp_path / "gh_output").read_text(encoding="utf-8", errors="replace")
    verdict = ""
    for line in outputs.splitlines():
        if line.startswith("verdict="):
            verdict = line.split("=", 1)[1]
    return proc.returncode, verdict


def test_a_clean_scan_passes_the_job(tmp_path) -> None:
    assert _run(tmp_path, exit_code=0, report='{"verdict":"pass","findings":[]}') == (0, "pass")


def test_a_genuine_warn_passes_the_job(tmp_path) -> None:
    """WARN is advisory by design - it must not block a merge."""
    assert _run(tmp_path, exit_code=1, report='{"verdict":"warn","findings":[1]}') == (0, "warn")


def test_a_fail_blocks_the_job(tmp_path) -> None:
    assert _run(tmp_path, exit_code=2, report='{"verdict":"fail","findings":[1]}')[0] != 0


@pytest.mark.parametrize(
    ("label", "report"),
    [
        pytest.param("no report at all", "", id="empty"),
        pytest.param("Traceback (most recent call last):", "traceback", id="traceback"),
        pytest.param('{"verdict":"fa', "partial json", id="truncated"),
    ],
)
def test_a_crash_that_exits_one_fails_closed(tmp_path, label: str, report: str) -> None:
    """EXIT 1 IS AMBIGUOUS AND IT IS THE DANGEROUS ONE.

    Ward returns 1 for a genuine WARN, and Python returns 1 for any uncaught
    exception - a broken install, a missing dependency, an interpreter crash
    mid-scan. Both landed on verdict=warn, which exits 0 and passes the job,
    so the single most likely way for this action to be broken produced a
    green tick.

    A real WARN leaves a report that says so; a crash does not. Requiring the
    report to corroborate the exit code is what separates them.
    """
    code, verdict = _run(tmp_path, exit_code=1, report=label)
    assert code == 2, f"a crashed scan ({report}) passed the job"
    assert verdict == "error"


@pytest.mark.parametrize("exit_code", [127, 137, 3, 255])
def test_an_unexpected_exit_code_fails_closed(tmp_path, exit_code: int) -> None:
    """127 is "ward not installed"; 137 is the OOM killer.

    Always exit 2, never the scanner's own code: exit 1 would be
    indistinguishable from a plain FAIL to anything reading the step status,
    and an unexpected code could itself be 0.
    """
    assert _run(tmp_path, exit_code=exit_code, report="")[0] == 2
