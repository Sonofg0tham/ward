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

import re
from functools import lru_cache
from pathlib import Path, PurePosixPath


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    """Translate a glob to a regex where ``*`` stays inside one path segment.

    ``fnmatch`` translates ``*`` to ``.*``, which crosses ``/``. That made
    every pattern implicitly recursive: a maintainer writing ``docs/*`` to
    skip the top-level pages also silenced content scanning for
    ``docs/internal/anything/evil.md``, with nothing to say more had been
    suppressed than was asked for. Since ``.wardignore`` is committed, an
    attacker can read it and place a payload at the deeper path.

    Segment-aware instead, matching the documented behaviour:
      ``*``    any run of characters within one segment
      ``**``   any run of characters, crossing segments
      ``**/``  zero or more leading directories
      ``?``    one character, not a separator
    """
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            if pattern.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
            elif pattern.startswith("**", i):
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif ch == "?":
            out.append("[^/]")
            i += 1
        elif ch == "[":
            close = pattern.find("]", i + 1)
            if close == -1:
                out.append(re.escape(ch))
                i += 1
            else:
                body = pattern[i + 1 : close]
                negate = body.startswith("!")
                if negate:
                    body = body[1:]
                # Escape the body per character, keeping range hyphens intact.
                # Splicing it raw let a pattern like `app/\[slug\]/**` produce
                # `[slug\]`, whose trailing backslash swallowed the closing
                # bracket and made the whole regex unparseable.
                safe = "".join(c if c == "-" else re.escape(c) for c in body)
                out.append("[" + ("^" if negate else "") + safe + "]")
                i = close + 1
        else:
            out.append(re.escape(ch))
            i += 1
    try:
        return re.compile(r"\A" + "".join(out) + r"\Z")
    except re.error:
        # A pattern we cannot translate must not abort the scan with a
        # traceback (exit 1 = WARN to the action, and a zero-byte report).
        # Fall back to an exact literal match: it suppresses less than the
        # author intended, which is the safe direction for a scanner.
        return re.compile(r"\A" + re.escape(pattern) + r"\Z")


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
        if _compile(pattern).match(normalised):
            return True
        # A LITERAL directory pattern ("build", "docs/generated/") covers the
        # subtree beneath it, matching .gitignore intuition. Restricted to
        # patterns with no glob characters of their own - otherwise "docs/*"
        # would expand to "docs/*/**" and quietly become recursive again,
        # which is the behaviour this module is fixing.
        if any(ch in pattern for ch in "*?["):
            continue
        if _compile(pattern.rstrip("/") + "/**").match(normalised):
            return True
    return False
