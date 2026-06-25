"""Command-line interface for Secret Scanner CLI."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import cast

from secret_scanner.github_client import GitHubClient, GitHubClientError
from secret_scanner.models import Confidence, Finding
from secret_scanner.reporter import (
    OutputFormat,
    filter_findings_by_severity,
    render_report,
)
from secret_scanner.scanner import (
    DEFAULT_MAX_HISTORY_COMMITS,
    OrganizationScanResult,
    RepositoryScanError,
    RepositoryScanner,
    parse_exclude_patterns,
)

DEFAULT_BRANCH = "main"


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return asyncio.run(_run(args))
    except (GitHubClientError, RepositoryScanError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Defensive CLI for authorized GitHub secret scanning.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan_parser = subcommands.add_parser("scan", help="Scan GitHub repositories.")
    scan_subcommands = scan_parser.add_subparsers(dest="scan_target", required=True)

    repo_parser = scan_subcommands.add_parser(
        "repo",
        help="Scan a single public or authorized GitHub repository.",
    )
    repo_parser.add_argument("repo", help="Repository in owner/repo format.")
    repo_parser.add_argument(
        "--branch",
        default=DEFAULT_BRANCH,
        help=f"Branch to scan. Defaults to {DEFAULT_BRANCH}.",
    )
    repo_parser.add_argument(
        "--exclude",
        default="",
        help='Comma-separated file path or glob patterns, e.g. "*.min.js,dist/*".',
    )
    repo_parser.add_argument(
        "--severity",
        choices=("low", "medium", "high"),
        help="Minimum confidence level to include in the report.",
    )
    repo_parser.add_argument(
        "--output",
        choices=("terminal", "json", "html"),
        default="terminal",
        help="Report format. Defaults to terminal.",
    )
    repo_parser.add_argument(
        "--output-file",
        type=Path,
        help="Write the report to a file instead of stdout.",
    )
    repo_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )
    repo_parser.add_argument(
        "--include-history",
        action="store_true",
        help=(
            "Also scan added lines from recent commit diffs, catching secrets "
            "that were committed and later removed from the current tree."
        ),
    )
    repo_parser.add_argument(
        "--max-commits",
        type=int,
        default=DEFAULT_MAX_HISTORY_COMMITS,
        help=(
            "Number of recent commits to scan when --include-history is set. "
            f"Defaults to {DEFAULT_MAX_HISTORY_COMMITS}."
        ),
    )
    repo_parser.set_defaults(handler=_scan_repo)

    org_parser = scan_subcommands.add_parser(
        "org",
        help="Scan all public repositories in a GitHub organization.",
    )
    org_parser.add_argument("org", help="GitHub organization name.")
    org_parser.add_argument(
        "--branch",
        help="Branch to scan in every repo. Defaults to each repo default branch.",
    )
    org_parser.add_argument(
        "--exclude",
        default="",
        help='Comma-separated file path or glob patterns, e.g. "*.min.js,dist/*".',
    )
    org_parser.add_argument(
        "--severity",
        choices=("low", "medium", "high"),
        help="Minimum confidence level to include in the report.",
    )
    org_parser.add_argument(
        "--output",
        choices=("terminal", "json", "html"),
        default="terminal",
        help="Report format. Defaults to terminal.",
    )
    org_parser.add_argument(
        "--output-file",
        type=Path,
        help="Write the report to a file instead of stdout.",
    )
    org_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )
    org_parser.set_defaults(handler=_scan_org)

    return parser


async def _run(args: argparse.Namespace) -> int:
    handler = args.handler
    return await handler(args)


async def _scan_repo(args: argparse.Namespace) -> int:
    async with GitHubClient() as github_client:
        scanner = RepositoryScanner(github_client)
        exclude_patterns = parse_exclude_patterns(args.exclude)
        findings = await scanner.scan_repo(
            args.repo,
            branch=args.branch,
            exclude_patterns=exclude_patterns,
        )

        if args.include_history:
            findings = findings + await scanner.scan_repo_history(
                args.repo,
                branch=args.branch,
                max_commits=args.max_commits,
                exclude_patterns=exclude_patterns,
            )

    _emit_report(findings, args)
    return 0


async def _scan_org(args: argparse.Namespace) -> int:
    async with GitHubClient() as github_client:
        scanner = RepositoryScanner(github_client)
        result = await scanner.scan_org(
            args.org,
            branch=args.branch,
            exclude_patterns=parse_exclude_patterns(args.exclude),
        )

    _emit_report(result.findings, args)
    _emit_scan_failures(result)
    return 2 if result.failures else 0


def _emit_report(findings: list[Finding], args: argparse.Namespace) -> None:
    filtered_findings = filter_findings_by_severity(
        findings,
        _optional_confidence(args.severity),
    )
    output_format = _output_format(args.output)
    output = render_report(
        filtered_findings,
        output_format=output_format,
        use_color=not args.no_color,
    )
    _write_output(output, args.output_file)


def _emit_scan_failures(result: OrganizationScanResult) -> None:
    for failure in result.failures:
        print(
            f"Warning: skipped {failure.repo}@{failure.branch}: {failure.error}",
            file=sys.stderr,
        )


def _optional_confidence(value: str | None) -> Confidence | None:
    if value is None:
        return None
    if value in {"low", "medium", "high"}:
        return cast(Confidence, value)

    raise ValueError(f"unsupported severity: {value}")


def _output_format(value: str) -> OutputFormat:
    if value in {"terminal", "json", "html"}:
        return cast(OutputFormat, value)

    raise ValueError(f"unsupported output format: {value}")


def _write_output(output: str, output_file: Path | None) -> None:
    if output_file is None:
        print(output)
        return

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(output + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
