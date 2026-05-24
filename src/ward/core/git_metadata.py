"""Pull untrusted metadata from a local git working tree."""

from __future__ import annotations

import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# File extensions whose content is treated as natural language by AI agents
# and is therefore prime injection territory.
DOC_SUFFIXES = frozenset({".md", ".markdown", ".txt", ".rst", ".adoc"})

# Source file extensions where we extract top-of-file comments only.
CODE_SUFFIXES = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".go",
        ".rs",
        ".rb",
        ".java",
        ".cs",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".php",
        ".sh",
        ".yml",
        ".yaml",
        ".tf",
    }
)


@dataclass(frozen=True)
class GitContext:
    """Snapshot of untrusted strings from a git working tree."""

    branch: str | None
    head_sha: str | None
    recent_commits: tuple[tuple[str, str], ...]  # (sha, message)
    tags: tuple[str, ...] = ()


def _run_git(args: list[str], cwd: Path) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def current_branch(cwd: Path) -> str | None:
    out = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd)
    return out or None


def head_sha(cwd: Path) -> str | None:
    out = _run_git(["rev-parse", "HEAD"], cwd)
    return out or None


def recent_commits(cwd: Path, limit: int = 20) -> list[tuple[str, str]]:
    """Return ``(sha, full message)`` for the last ``limit`` commits."""
    out = _run_git(
        ["log", f"-{limit}", "--no-color", "--pretty=format:%H%x1f%B%x1e"],
        cwd,
    )
    if not out:
        return []
    records: list[tuple[str, str]] = []
    for record in out.split("\x1e"):
        record = record.strip()
        if not record or "\x1f" not in record:
            continue
        sha, body = record.split("\x1f", 1)
        records.append((sha.strip(), body.strip()))
    return records


def tag_names(cwd: Path) -> list[str]:
    out = _run_git(["tag", "--list"], cwd)
    return [line.strip() for line in out.splitlines() if line.strip()]


def commit_message(cwd: Path, sha: str) -> str:
    return _run_git(["log", "-1", "--no-color", "--pretty=format:%B", sha], cwd)


def walk_tracked_files(cwd: Path) -> Iterable[Path]:
    out = _run_git(["ls-files"], cwd)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        yield cwd / line
