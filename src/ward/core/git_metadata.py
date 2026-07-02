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
    # Force UTF-8 decoding. git emits UTF-8; without this, Windows would use
    # the locale codepage (cp1252) and crash on any non-cp1252 byte - which
    # is exactly the adversarial unicode Ward exists to scan. errors="replace"
    # keeps a stray byte from taking the whole scan down.
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
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


def ref_exists(cwd: Path, ref: str) -> bool:
    """Return True if ``ref`` resolves to a commit in ``cwd``."""
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode == 0


def changed_files(cwd: Path, base_ref: str) -> set[str]:
    """Return repo-relative paths (forward-slash) changed since ``base_ref``.

    Union of three sets:
    - committed changes on this branch since the merge-base with ``base_ref``
      (``git diff --name-only base...HEAD``),
    - uncommitted working-tree modifications (staged and unstaged),
    - untracked files.

    Used by provenance-aware suppression: a ``ward-allow-file`` directive in
    any file returned here is attacker-controllable in the current change and
    must not be honoured. Assumes the caller has already verified ``base_ref``
    with :func:`ref_exists`.
    """
    files: set[str] = set()
    for args in (
        ["diff", "--name-only", f"{base_ref}...HEAD"],
        ["diff", "--name-only", "HEAD"],
        ["ls-files", "--others", "--exclude-standard"],
    ):
        for line in _run_git(args, cwd).splitlines():
            line = line.strip()
            if line:
                files.add(line.replace("\\", "/"))
    return files


def walk_tracked_files(cwd: Path) -> Iterable[Path]:
    out = _run_git(["ls-files"], cwd)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        yield cwd / line
