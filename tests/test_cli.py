from __future__ import annotations

import json
import shutil
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

import pytest

from secret_scanner import cli
from secret_scanner.models import Confidence, Finding
from secret_scanner.scanner import OrganizationScanResult, RepositoryScanFailure


class FakeGitHubClient:
    entered = False
    closed = False

    async def __aenter__(self) -> FakeGitHubClient:
        self.__class__.entered = True
        return self

    async def __aexit__(self, *_exc_info: object) -> None:
        self.__class__.closed = True


class FakeRepositoryScanner:
    calls: list[dict[str, Any]] = []
    findings: list[Finding] = []
    org_result: OrganizationScanResult | None = None

    def __init__(self, github_client: FakeGitHubClient) -> None:
        self.github_client = github_client

    async def scan_repo(
        self,
        repo_full_name: str,
        *,
        branch: str = "main",
        exclude_patterns: tuple[str, ...] = (),
        author_email: str = "",
    ) -> list[Finding]:
        self.__class__.calls.append(
            {
                "repo_full_name": repo_full_name,
                "branch": branch,
                "exclude_patterns": exclude_patterns,
                "author_email": author_email,
            }
        )
        return self.findings

    async def scan_org(
        self,
        org: str,
        *,
        branch: str | None = None,
        exclude_patterns: tuple[str, ...] = (),
        author_email: str = "",
    ) -> OrganizationScanResult:
        self.__class__.calls.append(
            {
                "org": org,
                "branch": branch,
                "exclude_patterns": exclude_patterns,
                "author_email": author_email,
            }
        )
        if self.org_result is not None:
            return self.org_result

        return OrganizationScanResult(findings=self.findings, failures=[])


def finding(*, confidence: Confidence = "high") -> Finding:
    return Finding(
        repo="example/repo",
        file_path="config/settings.env",
        line_number=5,
        matched_text="AKIA************ABCD",
        detection_method="regex",
        pattern_name="AWS Access Key ID",
        confidence=confidence,
        commit_sha="abc123",
        author_email="",
    )


@contextmanager
def report_path(*parts: str) -> Iterator[Path]:
    base_dir = Path("reports") / "test-cli" / uuid.uuid4().hex
    path = base_dir.joinpath(*parts)

    try:
        yield path
    finally:
        if base_dir.exists():
            shutil.rmtree(base_dir)
        with suppress(OSError):
            base_dir.parent.rmdir()
        with suppress(OSError):
            base_dir.parent.parent.rmdir()


@pytest.fixture(autouse=True)
def fake_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeGitHubClient.entered = False
    FakeGitHubClient.closed = False
    FakeRepositoryScanner.calls = []
    FakeRepositoryScanner.findings = [finding()]
    FakeRepositoryScanner.org_result = None
    monkeypatch.setattr(cli, "GitHubClient", FakeGitHubClient)
    monkeypatch.setattr(cli, "RepositoryScanner", FakeRepositoryScanner)


def test_scan_repo_outputs_terminal_report(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(
        [
            "scan",
            "repo",
            "example/repo",
            "--branch",
            "develop",
            "--exclude",
            "*.min.js,package-lock.json",
            "--no-color",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AWS Access Key ID" in captured.out
    assert "AKIA************ABCD" in captured.out
    assert captured.err == ""
    assert FakeGitHubClient.entered is True
    assert FakeGitHubClient.closed is True
    assert FakeRepositoryScanner.calls == [
        {
            "repo_full_name": "example/repo",
            "branch": "develop",
            "exclude_patterns": ("*.min.js", "package-lock.json"),
            "author_email": "",
        }
    ]


def test_scan_repo_writes_json_report(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with report_path("report.json") as output_file:
        exit_code = cli.main(
            [
                "scan",
                "repo",
                "example/repo",
                "--output",
                "json",
                "--output-file",
                str(output_file),
            ]
        )

        captured = capsys.readouterr()
        report = json.loads(output_file.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert captured.out == ""
    assert report["findings"][0]["matched_text"] == "AKIA************ABCD"


def test_scan_repo_creates_output_file_parent_directory(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with report_path("nested", "report.json") as output_file:
        exit_code = cli.main(
            [
                "scan",
                "repo",
                "example/repo",
                "--output",
                "json",
                "--output-file",
                str(output_file),
            ]
        )

        captured = capsys.readouterr()

        assert exit_code == 0
        assert captured.out == ""
        assert output_file.exists()


def test_scan_repo_filters_by_severity(capsys: pytest.CaptureFixture[str]) -> None:
    FakeRepositoryScanner.findings = [
        finding(confidence="low"),
        finding(confidence="high"),
    ]

    exit_code = cli.main(
        [
            "scan",
            "repo",
            "example/repo",
            "--severity",
            "high",
            "--output",
            "json",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 0
    assert [item["confidence"] for item in report["findings"]] == ["high"]


def test_scan_org_uses_default_branches_when_branch_is_omitted(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli.main(
        [
            "scan",
            "org",
            "example-org",
            "--exclude",
            "*.min.js",
            "--no-color",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "AWS Access Key ID" in captured.out
    assert captured.err == ""
    assert FakeRepositoryScanner.calls == [
        {
            "org": "example-org",
            "branch": None,
            "exclude_patterns": ("*.min.js",),
            "author_email": "",
        }
    ]


def test_scan_org_allows_branch_override_and_json_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    FakeRepositoryScanner.org_result = OrganizationScanResult(
        findings=[finding(confidence="medium"), finding(confidence="high")],
        failures=[],
    )

    exit_code = cli.main(
        [
            "scan",
            "org",
            "example-org",
            "--branch",
            "release",
            "--severity",
            "high",
            "--output",
            "json",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 0
    assert [item["confidence"] for item in report["findings"]] == ["high"]
    assert FakeRepositoryScanner.calls == [
        {
            "org": "example-org",
            "branch": "release",
            "exclude_patterns": (),
            "author_email": "",
        }
    ]


def test_scan_org_reports_partial_failures(
    capsys: pytest.CaptureFixture[str],
) -> None:
    FakeRepositoryScanner.org_result = OrganizationScanResult(
        findings=[finding()],
        failures=[
            RepositoryScanFailure(
                repo="example-org/web",
                branch="main",
                error="GitHub returned a truncated tree",
            )
        ],
    )

    exit_code = cli.main(["scan", "org", "example-org", "--no-color"])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "AWS Access Key ID" in captured.out
    assert "Warning: skipped example-org/web@main" in captured.err


def test_scan_repo_returns_error_for_scanner_failure(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class BrokenScanner(FakeRepositoryScanner):
        async def scan_repo(
            self,
            repo_full_name: str,
            *,
            branch: str = "main",
            exclude_patterns: tuple[str, ...] = (),
            author_email: str = "",
        ) -> list[Finding]:
            raise ValueError("repo_full_name must use the 'owner/repo' format")

    monkeypatch.setattr(cli, "RepositoryScanner", BrokenScanner)

    exit_code = cli.main(["scan", "repo", "invalid"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "owner/repo" in captured.err
