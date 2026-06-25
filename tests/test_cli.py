from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from secret_scanner import cli
from secret_scanner.baseline import write_baseline
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
    history_findings: list[Finding] = []
    org_result: OrganizationScanResult | None = None
    org_history_result: OrganizationScanResult | None = None

    def __init__(self, github_client: FakeGitHubClient) -> None:
        self.github_client = github_client

    async def scan_repo(
        self,
        repo_full_name: str,
        *,
        branch: str = "main",
        exclude_patterns: tuple[str, ...] = (),
    ) -> list[Finding]:
        self.__class__.calls.append(
            {
                "repo_full_name": repo_full_name,
                "branch": branch,
                "exclude_patterns": exclude_patterns,
            }
        )
        return self.findings

    async def scan_repo_history(
        self,
        repo_full_name: str,
        *,
        branch: str = "main",
        max_commits: int = 50,
        exclude_patterns: tuple[str, ...] = (),
    ) -> list[Finding]:
        self.__class__.calls.append(
            {
                "repo_history_full_name": repo_full_name,
                "branch": branch,
                "max_commits": max_commits,
                "exclude_patterns": exclude_patterns,
            }
        )
        return self.history_findings

    async def scan_org(
        self,
        org: str,
        *,
        branch: str | None = None,
        exclude_patterns: tuple[str, ...] = (),
    ) -> OrganizationScanResult:
        self.__class__.calls.append(
            {
                "org": org,
                "branch": branch,
                "exclude_patterns": exclude_patterns,
            }
        )
        if self.org_result is not None:
            return self.org_result

        return OrganizationScanResult(findings=self.findings, failures=[])

    async def scan_org_history(
        self,
        org: str,
        *,
        branch: str | None = None,
        max_commits: int = 50,
        exclude_patterns: tuple[str, ...] = (),
    ) -> OrganizationScanResult:
        self.__class__.calls.append(
            {
                "org_history": org,
                "branch": branch,
                "max_commits": max_commits,
                "exclude_patterns": exclude_patterns,
            }
        )
        if self.org_history_result is not None:
            return self.org_history_result

        return OrganizationScanResult(findings=self.history_findings, failures=[])


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
    )


@pytest.fixture(autouse=True)
def fake_scanner(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeGitHubClient.entered = False
    FakeGitHubClient.closed = False
    FakeRepositoryScanner.calls = []
    FakeRepositoryScanner.findings = [finding()]
    FakeRepositoryScanner.history_findings = []
    FakeRepositoryScanner.org_result = None
    FakeRepositoryScanner.org_history_result = None
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
        }
    ]


def test_scan_repo_writes_json_report(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "report.json"
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
    tmp_path: Path,
) -> None:
    output_file = tmp_path / "nested" / "report.json"
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


def test_scan_repo_write_baseline_writes_file_and_skips_report(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    baseline_path = tmp_path / "baseline.json"
    second_finding = Finding(
        repo="example/repo",
        file_path="other.env",
        line_number=1,
        matched_text="ghp_AAAA",
        detection_method="regex",
        pattern_name="GitHub personal access token",
        confidence="high",
        commit_sha="def456",
    )
    FakeRepositoryScanner.findings = [finding(), second_finding]

    exit_code = cli.main(
        [
            "scan",
            "repo",
            "example/repo",
            "--write-baseline",
            str(baseline_path),
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert "Wrote 2 finding(s)" in captured.out
    assert len(payload["accepted"]) == 2


def test_scan_repo_baseline_filters_previously_accepted_findings(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    accepted_finding = finding(confidence="high")
    new_finding = Finding(
        repo="example/repo",
        file_path="other.env",
        line_number=1,
        matched_text="brand-new-secret",
        detection_method="regex",
        pattern_name="AWS Access Key ID",
        confidence="high",
        commit_sha="def456",
    )
    baseline_path = tmp_path / "baseline.json"
    write_baseline(baseline_path, [accepted_finding])
    FakeRepositoryScanner.findings = [accepted_finding, new_finding]

    exit_code = cli.main(
        [
            "scan",
            "repo",
            "example/repo",
            "--baseline",
            str(baseline_path),
            "--output",
            "json",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 0
    assert [item["matched_text"] for item in report["findings"]] == ["brand-new-secret"]


def test_scan_repo_baseline_missing_file_returns_error(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    exit_code = cli.main(
        [
            "scan",
            "repo",
            "example/repo",
            "--baseline",
            str(tmp_path / "missing.json"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "baseline file not found" in captured.err


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
        }
    ]


def test_scan_repo_with_include_history_merges_findings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    FakeRepositoryScanner.findings = [finding(confidence="high")]
    FakeRepositoryScanner.history_findings = [finding(confidence="medium")]

    exit_code = cli.main(
        [
            "scan",
            "repo",
            "example/repo",
            "--include-history",
            "--max-commits",
            "10",
            "--output",
            "json",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 0
    assert [item["confidence"] for item in report["findings"]] == ["high", "medium"]
    assert {
        "repo_history_full_name": "example/repo",
        "branch": "main",
        "max_commits": 10,
        "exclude_patterns": (),
    } in FakeRepositoryScanner.calls


def test_scan_repo_without_include_history_skips_history_scan() -> None:
    cli.main(["scan", "repo", "example/repo", "--output", "json"])

    assert all(
        "repo_history_full_name" not in call for call in FakeRepositoryScanner.calls
    )


def test_scan_org_with_include_history_merges_findings_and_failures(
    capsys: pytest.CaptureFixture[str],
) -> None:
    FakeRepositoryScanner.org_result = OrganizationScanResult(
        findings=[finding(confidence="high")],
        failures=[
            RepositoryScanFailure(
                repo="example-org/tree-scan", branch="main", error="boom"
            )
        ],
    )
    FakeRepositoryScanner.org_history_result = OrganizationScanResult(
        findings=[finding(confidence="medium")],
        failures=[
            RepositoryScanFailure(
                repo="example-org/history-scan", branch="main", error="kaboom"
            )
        ],
    )

    exit_code = cli.main(
        [
            "scan",
            "org",
            "example-org",
            "--include-history",
            "--max-commits",
            "25",
            "--output",
            "json",
            "--no-color",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 2
    assert [item["confidence"] for item in report["findings"]] == ["high", "medium"]
    assert {
        "org_history": "example-org",
        "branch": None,
        "max_commits": 25,
        "exclude_patterns": (),
    } in FakeRepositoryScanner.calls


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


def test_scan_org_baseline_filters_findings_and_still_reports_failures(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    accepted_finding = finding(confidence="high")
    baseline_path = tmp_path / "baseline.json"
    write_baseline(baseline_path, [accepted_finding])
    FakeRepositoryScanner.org_result = OrganizationScanResult(
        findings=[accepted_finding],
        failures=[
            RepositoryScanFailure(repo="example-org/web", branch="main", error="boom")
        ],
    )

    exit_code = cli.main(
        [
            "scan",
            "org",
            "example-org",
            "--baseline",
            str(baseline_path),
            "--output",
            "json",
        ]
    )

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert exit_code == 2
    assert report["findings"] == []
    assert "Warning: skipped example-org/web@main" in captured.err


def test_scan_org_write_baseline_skips_report_but_still_reports_failures(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    baseline_path = tmp_path / "baseline.json"
    FakeRepositoryScanner.org_result = OrganizationScanResult(
        findings=[finding()],
        failures=[
            RepositoryScanFailure(repo="example-org/web", branch="main", error="boom")
        ],
    )

    exit_code = cli.main(
        ["scan", "org", "example-org", "--write-baseline", str(baseline_path)]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Wrote 1 finding(s)" in captured.out
    assert "Warning: skipped example-org/web@main" in captured.err
    assert baseline_path.exists()


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
        ) -> list[Finding]:
            raise ValueError("repo_full_name must use the 'owner/repo' format")

    monkeypatch.setattr(cli, "RepositoryScanner", BrokenScanner)

    exit_code = cli.main(["scan", "repo", "invalid"])
    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""
    assert "owner/repo" in captured.err
