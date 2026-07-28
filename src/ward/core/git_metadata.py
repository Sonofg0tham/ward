"""Pull untrusted metadata from a local git working tree."""

from __future__ import annotations

import os
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


class GitError(RuntimeError):
    """A git command Ward depends on could not be run or failed.

    Distinguishing "git said no" from "git returned nothing" matters: several
    callers previously read a failure as an empty result, which silently
    downgraded a broken scan into a clean one.
    """


def _git(args: list[str], cwd: Path, *, check: bool = False) -> str:
    """Run git and return raw stdout.

    ``core.quotePath=false`` stops git octal-escaping non-ASCII paths and
    wrapping them in quotes. With the default on, a tracked file named
    ``réadme.md`` comes back as ``"r\\303\\251adme.md"``, whose suffix is
    ``.md"`` - so it matches no known extension and its content is never
    scanned at all.

    Force UTF-8 decoding. git emits UTF-8; without this, Windows would use the
    locale codepage (cp1252) and crash on any non-cp1252 byte - which is
    exactly the adversarial unicode Ward exists to scan. errors="replace"
    keeps a stray byte from taking the whole scan down.

    With ``check=True`` a non-zero exit raises :class:`GitError` instead of
    returning "". Use it wherever an empty result would be indistinguishable
    from a successful scan of nothing.
    """
    try:
        result = subprocess.run(
            ["git", "-c", "core.quotePath=false", *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        # git missing from PATH, or cwd is not a usable directory. Both are
        # operational failures, never "the repo is clean".
        raise GitError(f"could not run git in {cwd}: {exc}") from exc
    if result.returncode != 0:
        if check:
            detail = (result.stderr or "").strip() or f"exit {result.returncode}"
            raise GitError(f"git {' '.join(args)} failed: {detail}")
        return ""
    return result.stdout


def _run_git(args: list[str], cwd: Path) -> str:
    return _git(args, cwd).strip()


def _git_paths(args: list[str], cwd: Path, *, check: bool = False) -> list[str]:
    """Run a path-listing git command with -z and split on NUL.

    NUL separation is the only encoding-safe way to read paths from git: a
    filename may legitimately contain a newline, a quote, or leading and
    trailing whitespace, all of which line-splitting plus ``.strip()`` would
    mangle into a path that never matches the file on disk.
    """
    out = _git([*args, "-z"], cwd, check=check)
    return [part for part in out.split("\0") if part]


def is_git_repo(cwd: Path) -> bool:
    """Return True if ``cwd`` sits inside a git working tree."""
    try:
        return bool(_git(["rev-parse", "--git-dir"], cwd).strip())
    except GitError:
        return False


def repo_prefix(cwd: Path) -> str:
    """Path of ``cwd`` relative to the git root, forward-slashed, or "".

    Everything git reports - ``diff --name-only``, ``ls-files`` - is relative
    to the REPOSITORY ROOT, but ``--repo`` may point anywhere inside the tree.
    Without this, a caller scanning a subdirectory compares "doc.md" against a
    changed-file set containing "pkg/doc.md", nothing ever matches, and every
    provenance gate that asks "was this file changed in the PR?" silently
    answers no - which means trusted.

    Returns "" at the root, or e.g. "pkg" / "src/app" below it.
    """
    prefix = _git(["rev-parse", "--show-prefix"], cwd).strip()
    return prefix.rstrip("/")


def current_branch(cwd: Path) -> str | None:
    """Return the checked-out branch name, resolving a detached HEAD.

    ``rev-parse --abbrev-ref HEAD`` returns the literal string "HEAD" when the
    checkout is detached, which is what ``actions/checkout`` leaves behind on a
    ``pull_request`` event (HEAD sits on ``refs/pull/N/merge``). Scanning the
    string "HEAD" means the real branch name is never scanned at all - so a
    branch called ``ignore-all-previous-instructions`` sails through the one
    surface Ward exists to check.
    """
    out = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd)
    if out and out != "HEAD":
        return out
    # Detached. Try the symbolic ref, then the refs CI hands us, then a
    # reverse lookup. Never fall back to the literal "HEAD".
    symbolic = _run_git(["symbolic-ref", "--quiet", "--short", "HEAD"], cwd)
    if symbolic:
        return symbolic
    for var in ("GITHUB_HEAD_REF", "GITHUB_REF_NAME"):
        value = os.environ.get(var, "").strip()
        if value and value != "HEAD":
            return value
    named = _run_git(["name-rev", "--name-only", "--exclude=tags/*", "HEAD"], cwd)
    if named and named != "undefined":
        # name-rev decorates with ~N / ^N for ancestors; keep the ref part.
        return named.split("~")[0].split("^")[0] or None
    return None


def head_sha(cwd: Path) -> str | None:
    out = _run_git(["rev-parse", "HEAD"], cwd)
    return out or None


def recent_commits(cwd: Path, limit: int = 20) -> list[tuple[str, str]]:
    """Return ``(sha, full message)`` for the last ``limit`` commits.

    Records are NUL-separated. U+001E was the obvious choice for a record
    separator right up until you notice a commit message may contain it: git's
    default cleanup preserves the byte, so an attacker who put U+001E in their
    message split their own record in two, and the half carrying the payload
    had no field separator and was silently dropped. NUL is the one byte git
    guarantees cannot appear in a commit message.
    """
    out = _git(
        ["log", f"-{limit}", "--no-color", "-z", "--pretty=format:%H%x1f%B"],
        cwd,
    )
    if not out.strip():
        return []
    records: list[tuple[str, str]] = []
    for record in out.split("\0"):
        if not record.strip():
            continue
        if "\x1f" not in record:
            # A record we cannot parse is a commit we did not scan. Surface it
            # rather than dropping it, so it cannot hide a payload.
            raise GitError(
                "could not parse a commit record from git log; refusing to "
                "report a partial scan of the history"
            )
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
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        raise GitError(f"could not run git in {cwd}: {exc}") from exc
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

    Raises:
        GitError: if any of the three commands fails. This must never degrade
            to an empty set. A shallow clone - which is what
            ``actions/checkout`` produces by default - makes
            ``diff base...HEAD`` fail with "no merge base"; treating that as
            "nothing changed" would mean every suppression directive in the
            PR is trusted, turning ``--suppression-base`` into full trust
            precisely when it is most needed.
    """
    files: set[str] = set()
    for args in (
        ["diff", "--name-only", f"{base_ref}...HEAD"],
        ["diff", "--name-only", "HEAD"],
        ["ls-files", "--others", "--exclude-standard"],
    ):
        for path in _git_paths(args, cwd, check=True):
            files.add(path.replace("\\", "/"))
    return files


def walk_tracked_files(cwd: Path) -> Iterable[Path]:
    for path in _git_paths(["ls-files"], cwd):
        yield cwd / path
