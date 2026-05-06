from __future__ import annotations

import asyncio

import pytest

from secret_scanner.models import GitTree, GitTreeItem
from secret_scanner.scanner import (
    RepositoryScanError,
    RepositoryScanner,
    parse_exclude_patterns,
    parse_repo_full_name,
    path_matches_any_pattern,
)


class FakeGitHubClient:
    def __init__(
        self,
        *,
        tree: GitTree,
        blobs: dict[str, str | None],
        branch_sha: str = "commit-sha",
    ) -> None:
        self.tree = tree
        self.blobs = blobs
        self.branch_sha = branch_sha
        self.branch_calls: list[tuple[str, str, str]] = []
        self.tree_calls: list[tuple[str, str, str, bool]] = []
        self.blob_calls: list[tuple[str, str, str]] = []
        self.active_blob_calls = 0
        self.max_active_blob_calls = 0
        self.release_blob_calls: asyncio.Event | None = None

    async def get_branch_sha(self, owner: str, repo: str, branch: str) -> str:
        self.branch_calls.append((owner, repo, branch))
        return self.branch_sha

    async def get_tree(
        self,
        owner: str,
        repo: str,
        sha: str,
        *,
        recursive: bool = True,
    ) -> GitTree:
        self.tree_calls.append((owner, repo, sha, recursive))
        return self.tree

    async def get_blob(self, owner: str, repo: str, blob_sha: str) -> str | None:
        self.blob_calls.append((owner, repo, blob_sha))
        self.active_blob_calls += 1
        self.max_active_blob_calls = max(
            self.max_active_blob_calls,
            self.active_blob_calls,
        )
        try:
            if self.release_blob_calls is not None:
                await self.release_blob_calls.wait()
            return self.blobs[blob_sha]
        finally:
            self.active_blob_calls -= 1


def tree_item(
    path: str,
    sha: str,
    *,
    type_: str = "blob",
    size: int | None = 100,
) -> GitTreeItem:
    return GitTreeItem(
        path=path,
        mode="100644",
        type=type_,
        sha=sha,
        size=size,
    )


def test_parse_repo_full_name_accepts_owner_repo() -> None:
    assert parse_repo_full_name(" owner/repo ") == ("owner", "repo")


@pytest.mark.parametrize(
    "value",
    ["owner", "owner/repo/extra", "/repo", "owner/"],
)
def test_parse_repo_full_name_rejects_invalid_values(value: str) -> None:
    with pytest.raises(ValueError, match="owner/repo"):
        parse_repo_full_name(value)


def test_parse_exclude_patterns_handles_strings_and_iterables() -> None:
    assert parse_exclude_patterns("*.min.js, package-lock.json ,,docs/*") == (
        "*.min.js",
        "package-lock.json",
        "docs/*",
    )
    assert parse_exclude_patterns(["*.lock", "  build/*  "]) == (
        "*.lock",
        "build/*",
    )
    assert parse_exclude_patterns(None) == ()


def test_path_matches_any_pattern_uses_path_and_file_name() -> None:
    assert path_matches_any_pattern("dist/app.min.js", ["*.min.js"])
    assert path_matches_any_pattern("frontend/package-lock.json", ["package-lock.json"])
    assert path_matches_any_pattern("docs/private/key.txt", ["docs/private/*"])
    assert not path_matches_any_pattern("src/app.py", ["docs/*"])


@pytest.mark.asyncio
async def test_scan_repo_combines_regex_and_entropy_findings() -> None:
    access_key = "AKIA" + "0000000000000000"
    high_entropy_token = "qR8vN3pLx9/ZtY2mK5" + "sD7fG1hJ4aC6bE0wUiOoP"
    content = f"AWS_ACCESS_KEY_ID={access_key}\nAPP_SECRET={high_entropy_token}\n"
    client = FakeGitHubClient(
        tree=GitTree(
            sha="tree-sha",
            truncated=False,
            tree=[tree_item("config/settings.env", "blob-1", size=len(content))],
        ),
        blobs={"blob-1": content},
        branch_sha="commit-123",
    )
    scanner = RepositoryScanner(client)

    findings = await scanner.scan_repo(
        "example/repo",
        branch="develop",
        author_email="author@example.com",
    )

    assert client.branch_calls == [("example", "repo", "develop")]
    assert client.tree_calls == [("example", "repo", "commit-123", True)]
    assert [finding.detection_method for finding in findings] == ["regex", "entropy"]
    assert {finding.file_path for finding in findings} == {"config/settings.env"}
    assert {finding.repo for finding in findings} == {"example/repo"}
    assert {finding.commit_sha for finding in findings} == {"commit-123"}
    assert {finding.author_email for finding in findings} == {"author@example.com"}
    assert all("*" in finding.matched_text for finding in findings)


@pytest.mark.asyncio
async def test_scan_repository_skips_excluded_large_non_blob_and_binary_items() -> None:
    client = FakeGitHubClient(
        tree=GitTree(
            sha="tree-sha",
            truncated=False,
            tree=[
                tree_item("src/app.py", "blob-scan"),
                tree_item("dist/app.min.js", "blob-minified"),
                tree_item("fixtures/package-lock.json", "blob-lock"),
                tree_item("large.txt", "blob-large", size=101),
                tree_item("docs", "tree-sha", type_="tree", size=None),
                tree_item("binary.dat", "blob-binary"),
            ],
        ),
        blobs={
            "blob-scan": "token = " + ("a" * 40),
            "blob-minified": "should not be fetched",
            "blob-lock": "should not be fetched",
            "blob-large": "should not be fetched",
            "tree-sha": "should not be fetched",
            "blob-binary": None,
        },
    )
    scanner = RepositoryScanner(client, max_file_size_bytes=100)

    findings = await scanner.scan_repository(
        "example",
        "repo",
        exclude_patterns=("src/ignored.py",),
    )

    assert findings == []
    assert client.blob_calls == [
        ("example", "repo", "blob-scan"),
        ("example", "repo", "blob-binary"),
    ]


@pytest.mark.asyncio
async def test_scan_repository_honors_per_call_exclude_patterns() -> None:
    client = FakeGitHubClient(
        tree=GitTree(
            sha="tree-sha",
            truncated=False,
            tree=[
                tree_item("src/scan.py", "blob-scan"),
                tree_item("src/skip.py", "blob-skip"),
            ],
        ),
        blobs={
            "blob-scan": "token = " + ("a" * 40),
            "blob-skip": "should not be fetched",
        },
    )
    scanner = RepositoryScanner(client)

    await scanner.scan_repository(
        "example",
        "repo",
        exclude_patterns=parse_exclude_patterns("src/skip.py"),
    )

    assert client.blob_calls == [("example", "repo", "blob-scan")]


@pytest.mark.asyncio
async def test_scan_repository_rejects_truncated_trees() -> None:
    client = FakeGitHubClient(
        tree=GitTree(
            sha="tree-sha",
            truncated=True,
            tree=[tree_item("src/app.py", "blob-scan")],
        ),
        blobs={"blob-scan": "should not be fetched"},
    )
    scanner = RepositoryScanner(client)

    with pytest.raises(RepositoryScanError, match="truncated tree"):
        await scanner.scan_repo("example/repo")

    assert client.blob_calls == []


@pytest.mark.asyncio
async def test_scan_repository_limits_blob_fetch_concurrency() -> None:
    release_blob_calls = asyncio.Event()
    client = FakeGitHubClient(
        tree=GitTree(
            sha="tree-sha",
            truncated=False,
            tree=[
                tree_item("one.txt", "blob-1"),
                tree_item("two.txt", "blob-2"),
                tree_item("three.txt", "blob-3"),
            ],
        ),
        blobs={
            "blob-1": "safe content",
            "blob-2": "safe content",
            "blob-3": "safe content",
        },
    )
    client.release_blob_calls = release_blob_calls
    scanner = RepositoryScanner(client, max_concurrency=2)

    scan_task = asyncio.create_task(scanner.scan_repo("example/repo"))
    for _ in range(100):
        if client.max_active_blob_calls >= 2:
            break
        await asyncio.sleep(0.01)
    else:
        release_blob_calls.set()
        await scan_task
        pytest.fail(
            "scan_repo did not reach max_active_blob_calls == 2 within the timeout"
        )

    assert client.max_active_blob_calls == 2

    release_blob_calls.set()
    await scan_task

    assert len(client.blob_calls) == 3
    assert client.max_active_blob_calls == 2


@pytest.mark.parametrize(
    ("max_file_size_bytes", "max_concurrency", "message"),
    [
        (-1, 1, "max_file_size_bytes"),
        (1, 0, "max_concurrency"),
    ],
)
def test_repository_scanner_rejects_invalid_limits(
    max_file_size_bytes: int,
    max_concurrency: int,
    message: str,
) -> None:
    client = FakeGitHubClient(
        tree=GitTree(sha="tree-sha", truncated=False, tree=[]),
        blobs={},
    )

    with pytest.raises(ValueError, match=message):
        RepositoryScanner(
            client,
            max_file_size_bytes=max_file_size_bytes,
            max_concurrency=max_concurrency,
        )
