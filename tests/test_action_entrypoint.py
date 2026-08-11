"""The composite action must never report a green job for a scan that failed.

`action/entrypoint.sh` is what every Marketplace user actually runs, and it
owns the mapping from Ward's exit code to the job's. These drive it with a
stub `ward` on PATH, so every exit code and report shape is exercised without
touching the GitHub API: what is under test is the shell script's decisions,
not the scanner's.

Extended in 0.3.1 with the exit-2 half of the corroboration check, the report
output, the job summary and the format defaults. The exit-1 cases below are
the original set and predate that.

What this file CANNOT cover is `action.yml` itself - that its inputs reach
the entrypoint, that its step ids and outputs line up, that it is a valid
composite action at all. Nothing ran it until the `action` job in ci.yml.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "action" / "entrypoint.sh"

BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(
    BASH is None, reason="bash is required to run the action entrypoint"
)


def run_entrypoint(
    tmp_path: Path,
    *,
    exit_code: int = 0,
    report_body: str | None = None,
    fmt: str = "sarif",
    pr: str = "42",
    install_ward: bool = True,
) -> dict[str, object]:
    """Drive entrypoint.sh with a stub `ward` that exits how we tell it to."""
    work = tmp_path / "work"
    work.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    if install_ward:
        body = "" if report_body is None else report_body
        stub = bin_dir / "ward"
        # Writes the report to stdout, which entrypoint.sh redirects to a file.
        stub.write_text(
            f"#!/usr/bin/env bash\nprintf '%s' {shell_quote(body)}\nexit {exit_code}\n",
            encoding="utf-8",
            newline="\n",
        )
        stub.chmod(0o755)

    github_output = work / "gh_output"
    github_summary = work / "gh_summary"
    github_output.write_text("", encoding="utf-8")
    github_summary.write_text("", encoding="utf-8")

    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_OUTPUT": str(github_output),
        "GITHUB_STEP_SUMMARY": str(github_summary),
        "GITHUB_REPOSITORY": "acme/widgets",
        "WARD_PR_INPUT": pr,
        "WARD_REPO_INPUT": "",
        "WARD_FAIL_ON": "high",
        "WARD_THRESHOLD": "low",
        "WARD_FORMAT": fmt,
        "WARD_OUTPUT": "",
        "WARD_RULE_PACK": "",
    }
    env.pop("GITHUB_EVENT_PATH", None)

    proc = subprocess.run(
        [str(BASH), str(ENTRYPOINT)],
        cwd=work,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    outputs: dict[str, str] = {}
    for line in github_output.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            outputs[key] = value
    return {
        "code": proc.returncode,
        "outputs": outputs,
        "stdout": proc.stdout + proc.stderr,
        "summary": github_summary.read_text(encoding="utf-8"),
    }


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


PASS_SARIF = '{"version": "2.1.0", "runs": [{"results": []}]}'
WARN_SARIF = '{"version": "2.1.0", "verdict": "warn", "runs": [{"results": [1]}]}'
FAIL_SARIF = '{"version": "2.1.0", "verdict": "fail", "runs": [{"results": [1, 2]}]}'


# --- the contract ----------------------------------------------------------


def test_a_clean_scan_passes_the_job(tmp_path) -> None:
    r = run_entrypoint(tmp_path, exit_code=0, report_body=PASS_SARIF)
    assert r["code"] == 0
    assert r["outputs"]["verdict"] == "pass"
    assert r["outputs"]["report"] == "ward-report.sarif"


def test_a_genuine_warn_passes_the_job(tmp_path) -> None:
    """A WARN is below `fail-on` by definition, so it must not fail the job."""
    r = run_entrypoint(tmp_path, exit_code=1, report_body=WARN_SARIF)
    assert r["code"] == 0
    assert r["outputs"]["verdict"] == "warn"


def test_a_genuine_fail_fails_the_job(tmp_path) -> None:
    r = run_entrypoint(tmp_path, exit_code=2, report_body=FAIL_SARIF)
    assert r["code"] == 1, "a detection did not fail the step"
    assert r["outputs"]["verdict"] == "fail"


# --- fail closed -----------------------------------------------------------


def test_a_crash_masquerading_as_warn_fails_closed(tmp_path) -> None:
    """Python exits 1 on any uncaught exception, and so does Ward on a WARN.

    A crash leaves no report. Without the corroboration check this is the
    single most likely way for the action to be broken, and it produced a
    green tick.
    """
    r = run_entrypoint(tmp_path, exit_code=1, report_body="")
    assert r["code"] == 2, "a crash was reported as a passing WARN"
    assert r["outputs"]["verdict"] == "error"


@pytest.mark.parametrize(
    "report_body",
    [
        pytest.param("Traceback (most recent call last):", id="traceback"),
        pytest.param('{"verdict":"fa', id="truncated-json"),
        pytest.param('{"verdict":"pass","findings":[]}', id="says-pass-not-warn"),
    ],
)
def test_a_warn_whose_report_does_not_say_warn_fails_closed(tmp_path, report_body: str) -> None:
    """A partial write is the interesting one: the file is not empty, so the
    size check alone would let it through."""
    r = run_entrypoint(tmp_path, exit_code=1, report_body=report_body)
    assert r["code"] == 2
    assert r["outputs"]["verdict"] == "error"


def test_a_fail_with_no_report_fails_closed_as_error(tmp_path) -> None:
    """Exit 2 is Ward's FAIL and also its fail-closed code for never having
    run - a rule pack that will not load exits 2 having written nothing. That
    reported `verdict=fail`, telling the workflow injection was found in a PR
    that was never scanned, and handed a zero-byte SARIF to Code Scanning.
    """
    r = run_entrypoint(tmp_path, exit_code=2, report_body="")
    assert r["outputs"]["verdict"] == "error", "a rule-pack error claimed injection was found"
    assert r["outputs"]["report"] == "", "an empty report was still offered for SARIF upload"
    assert r["code"] == 2


@pytest.mark.parametrize("exit_code", [127, 137, 3, 255])
def test_an_unexpected_exit_code_fails_closed(tmp_path, exit_code: int) -> None:
    """127 is "ward not installed"; 137 is the OOM killer.

    Always exit 2, never the scanner's own code: exit 1 would be
    indistinguishable from a plain FAIL to anything reading the step status,
    and an unexpected code could itself be 0.
    """
    r = run_entrypoint(tmp_path, exit_code=exit_code, report_body="")
    assert r["code"] == 2
    assert r["outputs"]["verdict"] == "error"


def test_ward_not_installed_fails_closed(tmp_path) -> None:
    r = run_entrypoint(tmp_path, install_ward=False)
    assert r["code"] == 2, "a broken install did not fail the job"
    assert r["outputs"]["verdict"] == "error"


def test_no_pr_number_and_no_event_payload_fails_closed(tmp_path) -> None:
    r = run_entrypoint(tmp_path, pr="", exit_code=0, report_body=PASS_SARIF)
    assert r["code"] == 2
    assert "No PR number" in r["stdout"]


# --- what a human sees -----------------------------------------------------


def test_the_findings_reach_the_job_summary(tmp_path) -> None:
    """The whole report goes to a file, so without this a failing run showed
    the maintainer a red tick and nothing else."""
    r = run_entrypoint(tmp_path, exit_code=2, report_body=FAIL_SARIF)
    assert "## Ward: fail" in r["summary"]
    assert "acme/widgets#42" in r["summary"]
    assert FAIL_SARIF in r["summary"], "the report was not included in the summary"


def test_a_clean_run_says_so_without_dumping_the_report(tmp_path) -> None:
    r = run_entrypoint(tmp_path, exit_code=0, report_body=PASS_SARIF)
    assert "## Ward: pass" in r["summary"]
    assert PASS_SARIF not in r["summary"]


@pytest.mark.parametrize(
    ("fmt", "expected"),
    [("sarif", "ward-report.sarif"), ("json", "ward-report.json"), ("pretty", "ward-report.txt")],
)
def test_the_default_report_name_follows_the_format(tmp_path, fmt: str, expected: str) -> None:
    r = run_entrypoint(tmp_path, exit_code=0, report_body=PASS_SARIF, fmt=fmt)
    assert r["outputs"]["report"] == expected
