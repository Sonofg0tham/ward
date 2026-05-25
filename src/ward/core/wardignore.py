"""``.wardignore`` support.

When ``ward scan-local`` runs, it looks for a ``.wardignore`` file at the
repo root. The file lists fnmatch-style glob patterns, one per line, with
``#`` comments and blank lines allowed. Tracked files whose relative path
matches any glob have their CONTENT skipped (we still scan the filename
itself, since a malicious filename inside an ignored directory remains
suspicious).

Format:

```
# Lines starting with '#' are comments.
src/ward/**/*.py    # whole subtree
tests/fixtures/*    # one level
docs/*.md           # specific extension
```

The trailing-comment syntax mirrors ``.gitignore`` for familiarity.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath


def load_patterns(repo: Path) -> tuple[str, ...]:
    """Read ``.wardignore`` from ``repo``. Returns an empty tuple if absent."""
    wardignore = repo / ".wardignore"
    if not wardignore.is_file():
        return ()
    patterns: list[str] = []
    for raw in wardignore.read_text(encoding="utf-8", errors="replace").splitlines():
        # Strip trailing comments while preserving '#' inside a pattern only
        # if escaped (which fnmatch doesn't model anyway, so we keep it simple).
        line = raw.split("#", 1)[0].strip()
        if line:
            patterns.append(line)
    return tuple(patterns)


def is_ignored(relpath: str, patterns: tuple[str, ...]) -> bool:
    """Return True if ``relpath`` matches any of the supplied glob patterns.

    Paths are matched as POSIX-style strings regardless of the host OS so a
    ``.wardignore`` written on macOS works on Windows runners and vice
    versa.
    """
    if not patterns:
        return False
    normalised = PurePosixPath(relpath.replace("\\", "/")).as_posix()
    for pattern in patterns:
        # fnmatch's `**` is non-greedy across separators, but it does work
        # when combined with normal `*` segments. We try both the verbatim
        # pattern and a fallback that anchors with `**/` so trailing-glob
        # patterns like `src/ward/**` match.
        if fnmatchcase(normalised, pattern):
            return True
        if pattern.endswith("/**") and fnmatchcase(
            normalised, pattern + "/*"
        ):  # pragma: no cover - belt-and-braces
            return True
    return False
