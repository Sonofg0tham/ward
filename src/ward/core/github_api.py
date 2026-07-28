"""Minimal GitHub REST client for PR metadata extraction.

This module never touches the code in a PR. It only reads the surfaces an
agent would see before running its own tools: title, body, branch name,
commit messages, and file paths in the diff.

Authentication: ``GITHUB_TOKEN`` env var or ``GH_TOKEN``. Without a token,
requests still work against public repos but are subject to a low rate
limit.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

GITHUB_API = "https://api.github.com"

# Owner and repo are interpolated straight into the API path, so they are
# validated against GitHub's own naming rules before they get there. Without
# this, a ref like "a/../../evil#1" resolves to a completely different
# endpoint once the URL is normalised - with the caller's token attached.
_OWNER_RE = re.compile(r"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPO_RE = re.compile(r"\A[A-Za-z0-9_.-]{1,100}\Z")


@dataclass(frozen=True)
class PRMetadata:
    owner: str
    repo: str
    number: int
    title: str
    body: str
    head_ref: str
    base_ref: str
    head_sha: str
    commit_messages: tuple[tuple[str, str], ...]  # (sha, message)
    changed_file_paths: tuple[str, ...] = field(default_factory=tuple)


class GitHubError(RuntimeError):
    """Raised on any non-2xx GitHub response."""


def _token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ward-scanner",
    }
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _get(client: httpx.Client, path: str) -> Any:
    """GET a GitHub API path, raising GitHubError for anything that goes wrong.

    Every failure mode has to funnel into GitHubError. The CLI turns that into
    exit 2; an uncaught httpx or JSON exception would exit 1, which the GitHub
    Action reads as WARN and passes the job - a green tick on a PR nothing
    ever screened.
    """
    try:
        response = client.get(f"{GITHUB_API}{path}")
    except httpx.HTTPError as exc:
        raise GitHubError(f"request to GitHub failed for {path}: {exc}") from exc
    if response.status_code // 100 != 2:
        raise GitHubError(f"GET {path} -> {response.status_code}: {response.text}")
    try:
        return response.json()
    except ValueError as exc:
        # A proxy or captive portal can return 200 with an HTML body.
        raise GitHubError(f"GitHub returned a non-JSON response for {path}: {exc}") from exc


# GitHub's list endpoints return 30 items per page by default and 100 at
# most. Ward used to read one page and stop, so a PR with 35 commits had
# commits 31-35 never scanned at all - an attacker only had to push thirty
# innocuous commits before the payload. Same for the 31st changed file.
_PER_PAGE = 100

# A PR's commits endpoint is capped at 250 by GitHub and files at 3000, so
# beyond that no amount of paging returns the rest. The completeness check
# below turns that into a loud failure rather than a quiet partial scan.
_MAX_PAGES = 100


def _get_all(client: httpx.Client, path: str) -> list[Any]:
    """GET every page of a GitHub list endpoint.

    Follows the ``Link: rel="next"`` header rather than incrementing a page
    counter, because that is what GitHub documents as the stable contract.
    """
    joiner = "&" if "?" in path else "?"
    url = f"{GITHUB_API}{path}{joiner}per_page={_PER_PAGE}"
    items: list[Any] = []
    for _ in range(_MAX_PAGES):
        try:
            response = client.get(url)
        except httpx.HTTPError as exc:
            raise GitHubError(f"request to GitHub failed for {url}: {exc}") from exc
        if response.status_code // 100 != 2:
            raise GitHubError(f"GET {url} -> {response.status_code}: {response.text}")
        try:
            page = response.json()
        except ValueError as exc:
            raise GitHubError(f"GitHub returned a non-JSON response for {url}: {exc}") from exc
        if not isinstance(page, list):
            raise GitHubError(f"expected a list from {url}, got {type(page).__name__}")
        items.extend(page)

        next_url = response.links.get("next", {}).get("url")
        if not next_url:
            return items
        # The next URL comes from a response header, so it is only as
        # trustworthy as the connection. Refuse to follow it off GitHub:
        # otherwise a proxy could redirect paging to its own host and
        # receive the caller's token in the Authorization header.
        if not str(next_url).startswith(f"{GITHUB_API}/"):
            raise GitHubError(f"refusing to follow pagination off {GITHUB_API}: {next_url!r}")
        url = str(next_url)
    raise GitHubError(f"pagination did not terminate after {_MAX_PAGES} pages for {path}")


def _check_complete(kind: str, fetched: int, declared: object, ref: str) -> None:
    """Fail closed if GitHub says the PR has more items than we read.

    Ward's answer is only meaningful if it saw everything. A scan that
    silently skipped commit 251 is worse than no scan, because it reports
    PASS. The PR object states its own totals, so compare against those
    rather than trying to infer whether a server-side cap was hit.
    """
    if not isinstance(declared, int) or declared <= fetched:
        return
    raise GitHubError(
        f"{ref}: read {fetched} of {declared} {kind}. GitHub caps this endpoint "
        f"(250 commits, 3000 files), so Ward cannot see the whole PR and will "
        f"not report a verdict on part of it. Scan the merge result locally "
        f"with 'ward scan-local' instead."
    )


def fetch_pr_metadata(owner: str, repo: str, number: int) -> PRMetadata:
    """Fetch the metadata surfaces of a PR.

    Body and title are read verbatim from the PR. Commit messages and file
    paths are read from the PR's commits and files endpoints respectively,
    following pagination to the end in both cases.
    """
    with httpx.Client(headers=_headers(), timeout=30.0) as client:
        pr = _get(client, f"/repos/{owner}/{repo}/pulls/{number}")
        commits = _get_all(client, f"/repos/{owner}/{repo}/pulls/{number}/commits")
        files = _get_all(client, f"/repos/{owner}/{repo}/pulls/{number}/files")

    ref = f"{owner}/{repo}#{number}"
    _check_complete("commits", len(commits), pr.get("commits"), ref)
    _check_complete("changed files", len(files), pr.get("changed_files"), ref)

    commit_messages = tuple(
        (str(c["sha"]), str(c["commit"]["message"]))
        for c in commits
        if isinstance(c, dict) and "sha" in c and "commit" in c
    )
    changed_paths = tuple(
        str(f["filename"]) for f in files if isinstance(f, dict) and "filename" in f
    )

    return PRMetadata(
        owner=owner,
        repo=repo,
        number=number,
        title=str(pr.get("title", "")),
        body=str(pr.get("body") or ""),
        head_ref=str(pr.get("head", {}).get("ref", "")),
        base_ref=str(pr.get("base", {}).get("ref", "")),
        head_sha=str(pr.get("head", {}).get("sha", "")),
        commit_messages=commit_messages,
        changed_file_paths=changed_paths,
    )


def parse_pr_ref(ref: str) -> tuple[str, str, int]:
    """Parse ``owner/repo#123`` into its parts. Raises ``ValueError`` on bad input.

    Owner, repo and number are validated here rather than at the request, so
    nothing that could escape its path segment ever reaches the API URL.
    """
    if "#" not in ref or "/" not in ref:
        raise ValueError(f"Bad PR ref {ref!r}, expected 'owner/repo#NUMBER'")
    repo_part, num_part = ref.split("#", 1)
    if "/" not in repo_part:
        raise ValueError(f"Bad PR ref {ref!r}, expected 'owner/repo#NUMBER'")
    owner, repo = repo_part.split("/", 1)
    if not _OWNER_RE.match(owner):
        raise ValueError(
            f"Bad owner {owner!r} in PR ref {ref!r}: must be 1-39 alphanumeric "
            "characters or hyphens, not starting or ending with a hyphen."
        )
    if not _REPO_RE.match(repo) or repo in (".", ".."):
        raise ValueError(
            f"Bad repo {repo!r} in PR ref {ref!r}: must contain only letters, "
            "digits, '.', '-' or '_'."
        )
    try:
        number = int(num_part)
    except ValueError as exc:
        raise ValueError(f"Bad PR number in {ref!r}") from exc
    if number <= 0:
        raise ValueError(f"Bad PR number in {ref!r}: must be a positive integer")
    return owner, repo, number
