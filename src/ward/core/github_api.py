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
from dataclasses import dataclass, field
from typing import Any

import httpx

GITHUB_API = "https://api.github.com"


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
    response = client.get(f"{GITHUB_API}{path}")
    if response.status_code // 100 != 2:
        raise GitHubError(f"GET {path} -> {response.status_code}: {response.text}")
    return response.json()


def fetch_pr_metadata(owner: str, repo: str, number: int) -> PRMetadata:
    """Fetch the metadata surfaces of a PR.

    Body and title are read verbatim from the PR. Commit messages and file
    paths are read from the PR's commits and files endpoints respectively.
    """
    with httpx.Client(headers=_headers(), timeout=30.0) as client:
        pr = _get(client, f"/repos/{owner}/{repo}/pulls/{number}")
        commits = _get(client, f"/repos/{owner}/{repo}/pulls/{number}/commits")
        files = _get(client, f"/repos/{owner}/{repo}/pulls/{number}/files")

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
    """Parse ``owner/repo#123`` into its parts. Raises ``ValueError`` on bad input."""
    if "#" not in ref or "/" not in ref:
        raise ValueError(f"Bad PR ref {ref!r}, expected 'owner/repo#NUMBER'")
    repo_part, num_part = ref.split("#", 1)
    if "/" not in repo_part:
        raise ValueError(f"Bad PR ref {ref!r}, expected 'owner/repo#NUMBER'")
    owner, repo = repo_part.split("/", 1)
    try:
        number = int(num_part)
    except ValueError as exc:
        raise ValueError(f"Bad PR number in {ref!r}") from exc
    return owner, repo, number
