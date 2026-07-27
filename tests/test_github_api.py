"""Tests for the GitHub REST client.

Parsing is covered as pure functions; the fetch path runs against an
``httpx.MockTransport`` so no network is touched.
"""

from __future__ import annotations

import httpx
import pytest

from ward.core.github_api import (
    GitHubError,
    _headers,
    fetch_pr_metadata,
    parse_pr_ref,
)


def test_parse_pr_ref_happy_path():
    assert parse_pr_ref("sonofg0tham/ward#42") == ("sonofg0tham", "ward", 42)


def test_parse_pr_ref_allows_dots_and_underscores_in_repo():
    assert parse_pr_ref("acme/my.repo_name-1#7") == ("acme", "my.repo_name-1", 7)


@pytest.mark.parametrize(
    "ref",
    [
        "missing-hash",
        "no/repo",
        "owner/repo#not-a-number",
        "#42",
        "owner#42",
    ],
)
def test_parse_pr_ref_rejects_bad_input(ref: str):
    with pytest.raises(ValueError):
        parse_pr_ref(ref)


@pytest.mark.parametrize(
    "ref",
    [
        # Path traversal: httpx normalises the URL, so "a/../../evil" would
        # otherwise resolve to https://api.github.com/evil/pulls/1 with the
        # caller's token attached.
        "a/../../evil#1",
        "../x/repo#1",
        "owner/../../../users/victim#1",
        # Percent-encoded separators aiming at the same trick.
        "x%2f..%2f/y#2",
        "owner/re%2fpo#3",
        # Owners cannot start or end with a hyphen, or hold slashes.
        "-bad/repo#1",
        "bad-/repo#1",
        # Non-positive PR numbers are never valid.
        "owner/repo#0",
        "owner/repo#-5",
        # Bare relative path segments as the repo.
        "owner/.#1",
        "owner/..#1",
    ],
)
def test_parse_pr_ref_rejects_path_traversal_and_bad_names(ref: str):
    with pytest.raises(ValueError):
        parse_pr_ref(ref)


def test_owner_length_capped_at_github_limit():
    with pytest.raises(ValueError):
        parse_pr_ref(f"{'a' * 40}/repo#1")
    # 39 characters is GitHub's actual maximum and must still parse.
    owner, repo, number = parse_pr_ref(f"{'a' * 39}/repo#1")
    assert owner == "a" * 39
    assert (repo, number) == ("repo", 1)


# --- header / auth ----------------------------------------------------------


def test_headers_include_token_when_set(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_example")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert _headers()["Authorization"] == "Bearer ghp_example"


def test_headers_omit_authorization_when_no_token(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert "Authorization" not in _headers()


# --- fetch path -------------------------------------------------------------


def _install_transport(monkeypatch: pytest.MonkeyPatch, handler) -> list[str]:
    """Route every httpx.Client through a MockTransport. Returns the path log."""
    seen: list[str] = []
    real_client = httpx.Client

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return handler(request)

    def factory(**kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "Client", factory)
    return seen


def test_fetch_pr_metadata_maps_every_surface(monkeypatch: pytest.MonkeyPatch):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/commits"):
            return httpx.Response(
                200,
                json=[
                    {"sha": "abc123", "commit": {"message": "fix: tidy up"}},
                    {"malformed": True},  # skipped, no sha/commit
                ],
            )
        if path.endswith("/files"):
            return httpx.Response(
                200,
                json=[{"filename": "src/app.py"}, {"no_filename": True}],
            )
        return httpx.Response(
            200,
            json={
                "title": "Add feature",
                "body": None,  # GitHub returns null for an empty body
                "head": {"ref": "feat/x", "sha": "deadbeefcafe"},
                "base": {"ref": "main"},
            },
        )

    paths = _install_transport(monkeypatch, handler)
    meta = fetch_pr_metadata("acme", "widget", 42)

    assert meta.title == "Add feature"
    assert meta.body == ""  # null body normalises to empty string, never "None"
    assert meta.head_ref == "feat/x"
    assert meta.base_ref == "main"
    assert meta.head_sha == "deadbeefcafe"
    assert meta.commit_messages == (("abc123", "fix: tidy up"),)
    assert meta.changed_file_paths == ("src/app.py",)
    assert paths == [
        "/repos/acme/widget/pulls/42",
        "/repos/acme/widget/pulls/42/commits",
        "/repos/acme/widget/pulls/42/files",
    ]


def test_fetch_pr_metadata_raises_on_non_2xx(monkeypatch: pytest.MonkeyPatch):
    _install_transport(monkeypatch, lambda _r: httpx.Response(404, text="Not Found"))
    with pytest.raises(GitHubError) as excinfo:
        fetch_pr_metadata("acme", "widget", 42)
    assert "404" in str(excinfo.value)
