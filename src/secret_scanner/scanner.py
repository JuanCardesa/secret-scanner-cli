"""Repository scan orchestration."""

from __future__ import annotations

import asyncio
import fnmatch
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol, TypeVar

from secret_scanner.detectors.entropy_detector import EntropyDetector
from secret_scanner.detectors.regex_detector import RegexDetector
from secret_scanner.models import Finding, GitHubRepo, GitTree, GitTreeItem

DEFAULT_MAX_CONCURRENCY = 8
DEFAULT_MAX_FILE_SIZE_BYTES = 1_000_000
DEFAULT_MAX_REPO_CONCURRENCY = 2
DEFAULT_EXCLUDE_PATTERNS = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "*.min.js",
    "*.map",
)
T = TypeVar("T")


class GitHubRepositoryClient(Protocol):
    async def list_org_repos(self, org: str) -> list[GitHubRepo]:
        """Return public repositories for an organization."""
        ...

    async def get_branch_sha(self, owner: str, repo: str, branch: str) -> str:
        """Return the commit SHA for a branch."""
        ...

    async def get_tree(
        self,
        owner: str,
        repo: str,
        sha: str,
        *,
        recursive: bool = True,
    ) -> GitTree:
        """Return a Git tree for a commit or tree SHA."""
        ...

    async def get_blob(self, owner: str, repo: str, blob_sha: str) -> str | None:
        """Return decoded text content for a blob, or None for non-text blobs."""
        ...


class Detector(Protocol):
    def scan(
        self,
        content: str,
        *,
        repo: str = "",
        file_path: str = "",
        commit_sha: str = "",
        author_email: str = "",
    ) -> list[Finding]:
        """Scan content and return findings."""
        ...


class RepositoryScanError(RuntimeError):
    """Raised when a repository cannot be scanned completely."""


@dataclass(frozen=True)
class RepositoryScanFailure:
    repo: str
    branch: str
    error: str


@dataclass(frozen=True)
class OrganizationScanResult:
    findings: list[Finding]
    failures: list[RepositoryScanFailure]


class RepositoryScanner:
    def __init__(
        self,
        github_client: GitHubRepositoryClient,
        *,
        regex_detector: Detector | None = None,
        entropy_detector: Detector | None = None,
        exclude_patterns: Iterable[str] = DEFAULT_EXCLUDE_PATTERNS,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        max_repo_concurrency: int = DEFAULT_MAX_REPO_CONCURRENCY,
    ) -> None:
        if max_file_size_bytes < 0:
            raise ValueError("max_file_size_bytes must be >= 0")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be >= 1")
        if max_repo_concurrency < 1:
            raise ValueError("max_repo_concurrency must be >= 1")

        self._github_client = github_client
        self._regex_detector = regex_detector or RegexDetector()
        self._entropy_detector = entropy_detector or EntropyDetector()
        self._exclude_patterns = tuple(exclude_patterns)
        self._max_file_size_bytes = max_file_size_bytes
        self._max_concurrency = max_concurrency
        self._max_repo_concurrency = max_repo_concurrency

    async def scan_repo(
        self,
        repo_full_name: str,
        *,
        branch: str = "main",
        exclude_patterns: Iterable[str] = (),
        author_email: str = "",
    ) -> list[Finding]:
        owner, repo_name = parse_repo_full_name(repo_full_name)
        return await self.scan_repository(
            owner,
            repo_name,
            branch=branch,
            exclude_patterns=exclude_patterns,
            author_email=author_email,
        )

    async def scan_org(
        self,
        org: str,
        *,
        branch: str | None = None,
        exclude_patterns: Iterable[str] = (),
        author_email: str = "",
    ) -> OrganizationScanResult:
        repos = await self._github_client.list_org_repos(org)

        findings: list[Finding] = []
        failures: list[RepositoryScanFailure] = []
        for chunk in chunked(repos, self._max_repo_concurrency):
            results = await asyncio.gather(
                *(
                    self._scan_org_repo(
                        repo,
                        branch=branch,
                        exclude_patterns=exclude_patterns,
                        author_email=author_email,
                    )
                    for repo in chunk
                )
            )
            for result in results:
                findings.extend(result.findings)
                failures.extend(result.failures)

        return OrganizationScanResult(findings=findings, failures=failures)

    async def scan_repository(
        self,
        owner: str,
        repo_name: str,
        *,
        branch: str = "main",
        exclude_patterns: Iterable[str] = (),
        author_email: str = "",
    ) -> list[Finding]:
        repo_full_name = f"{owner}/{repo_name}"
        commit_sha = await self._github_client.get_branch_sha(owner, repo_name, branch)
        git_tree = await self._github_client.get_tree(
            owner,
            repo_name,
            commit_sha,
            recursive=True,
        )
        if git_tree.truncated:
            raise RepositoryScanError(
                "GitHub returned a truncated tree; refusing to scan partial results"
            )

        active_excludes = self._exclude_patterns + tuple(exclude_patterns)
        scan_targets = [
            item
            for item in git_tree.tree
            if self._should_scan_tree_item(item, active_excludes)
        ]

        findings: list[Finding] = []
        for chunk in chunked(scan_targets, self._max_concurrency):
            results = await asyncio.gather(
                *(
                    self._scan_tree_item(
                        owner,
                        repo_name,
                        repo_full_name,
                        item,
                        commit_sha=commit_sha,
                        author_email=author_email,
                    )
                    for item in chunk
                )
            )
            findings.extend(finding for group in results for finding in group)

        return findings

    async def _scan_org_repo(
        self,
        repo: GitHubRepo,
        *,
        branch: str | None,
        exclude_patterns: Iterable[str],
        author_email: str,
    ) -> OrganizationScanResult:
        target_branch = branch or repo.default_branch or "main"
        try:
            findings = await self.scan_repo(
                repo.full_name,
                branch=target_branch,
                exclude_patterns=exclude_patterns,
                author_email=author_email,
            )
        except Exception as exc:
            return OrganizationScanResult(
                findings=[],
                failures=[
                    RepositoryScanFailure(
                        repo=repo.full_name,
                        branch=target_branch,
                        error=str(exc),
                    )
                ],
            )

        return OrganizationScanResult(findings=findings, failures=[])

    def _should_scan_tree_item(
        self,
        item: GitTreeItem,
        exclude_patterns: Sequence[str],
    ) -> bool:
        if item.type != "blob":
            return False

        if item.size is not None and item.size > self._max_file_size_bytes:
            return False

        return not path_matches_any_pattern(item.path, exclude_patterns)

    async def _scan_tree_item(
        self,
        owner: str,
        repo_name: str,
        repo_full_name: str,
        item: GitTreeItem,
        *,
        commit_sha: str,
        author_email: str,
    ) -> list[Finding]:
        content = await self._github_client.get_blob(owner, repo_name, item.sha)

        if content is None:
            return []

        findings: list[Finding] = []
        for detector in (self._regex_detector, self._entropy_detector):
            findings.extend(
                detector.scan(
                    content,
                    repo=repo_full_name,
                    file_path=item.path,
                    commit_sha=commit_sha,
                    author_email=author_email,
                )
            )

        return findings


def parse_repo_full_name(repo_full_name: str) -> tuple[str, str]:
    parts = [part.strip() for part in repo_full_name.split("/")]
    if len(parts) != 2 or not all(parts):
        raise ValueError("repo_full_name must use the 'owner/repo' format")

    return parts[0], parts[1]


def chunked(items: Sequence[T], chunk_size: int) -> Iterable[Sequence[T]]:
    for start in range(0, len(items), chunk_size):
        yield items[start : start + chunk_size]


def parse_exclude_patterns(raw_excludes: str | Iterable[str] | None) -> tuple[str, ...]:
    if raw_excludes is None:
        return ()

    values: Iterable[str]
    if isinstance(raw_excludes, str):
        values = raw_excludes.split(",")
    else:
        values = raw_excludes

    return tuple(value.strip() for value in values if value.strip())


def path_matches_any_pattern(path: str, patterns: Iterable[str]) -> bool:
    normalized_path = path.replace("\\", "/")
    file_name = PurePosixPath(normalized_path).name

    return any(
        fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(file_name, pattern)
        for pattern in patterns
    )
