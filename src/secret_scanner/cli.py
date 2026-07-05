"""Command-line interface for Secret Scanner CLI."""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from secret_scanner import __version__
from secret_scanner.baseline import (
    filter_accepted_findings,
    load_baseline,
    write_baseline,
)
from secret_scanner.detectors.entropy_detector import (
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_HEX_ENTROPY_THRESHOLD,
    EntropyDetector,
)
from secret_scanner.github_client import GitHubClient, GitHubClientError
from secret_scanner.local_scanner import LocalScanError, LocalScanner
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return asyncio.run(_run(args))
    except (GitHubClientError, RepositoryScanError, LocalScanError, ValueError) as exc:
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
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan_parser = subcommands.add_parser("scan", help="Scan for exposed secrets.")
    scan_subcommands = scan_parser.add_subparsers(dest="scan_target", required=True)

    repo_parser = scan_subcommands.add_parser(
        "repo",
        help="Scan a single public or authorized GitHub repository.",
    )
    repo_parser.add_argument("repo", help="Repository in owner/repo format.")
    repo_parser.add_argument(
        "--branch",
        default=None,
        help="Branch to scan. Defaults to the repository's default branch.",
    )
    _add_history_args(repo_parser)
    _add_common_scan_args(repo_parser)
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
    _add_history_args(org_parser)
    _add_common_scan_args(org_parser)
    org_parser.set_defaults(handler=_scan_org)

    local_parser = scan_subcommands.add_parser(
        "local",
        help="Scan a local directory or file (no GitHub API involved).",
    )
    local_parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Local directory or file to scan. Defaults to the current directory.",
    )
    _add_common_scan_args(local_parser)
    local_parser.set_defaults(handler=_scan_local)

    return parser


def _add_history_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--include-history",
        action="store_true",
        help=(
            "Also scan added lines from recent commit diffs, catching secrets "
            "that were committed and later removed from the current tree."
        ),
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=DEFAULT_MAX_HISTORY_COMMITS,
        help=(
            "Number of recent commits to scan when --include-history is set. "
            f"Defaults to {DEFAULT_MAX_HISTORY_COMMITS}."
        ),
    )


def _add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--exclude",
        default="",
        help='Comma-separated file path or glob patterns, e.g. "*.min.js,dist/*".',
    )
    parser.add_argument(
        "--severity",
        choices=("low", "medium", "high"),
        help="Minimum confidence level to include in the report.",
    )
    parser.add_argument(
        "--output",
        choices=("terminal", "json", "html", "sarif"),
        default="terminal",
        help="Report format. Defaults to terminal.",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="Write the report to a file instead of stdout.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in terminal output.",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=None,
        help=(
            "Minimum Shannon entropy (bits/char) for the base64-class entropy "
            "detector. Lower values catch more but are noisier. Hex-only tokens "
            "use a proportionally lower threshold automatically."
        ),
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help=(
            "Exit with status code 3 if the report (after --severity and "
            "--baseline filtering) is non-empty. Useful for CI gating. Does not "
            "override a partial-scan failure (status code 2)."
        ),
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        help=(
            "Path to a baseline file. Findings matching an accepted fingerprint "
            "in it are excluded from the report."
        ),
    )
    parser.add_argument(
        "--write-baseline",
        type=Path,
        help=(
            "Write every finding from this scan to PATH as an accepted baseline, "
            "then exit. Combine with --baseline on later runs to surface only "
            "new findings."
        ),
    )


async def _run(args: argparse.Namespace) -> int:
    handler = args.handler
    return await handler(args)


async def _scan_repo(args: argparse.Namespace) -> int:
    async with GitHubClient() as github_client:
        scanner = RepositoryScanner(github_client, **_detector_kwargs(args))
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

    if args.write_baseline is not None:
        write_baseline(args.write_baseline, findings)
        print(
            f"Wrote {len(findings)} finding(s) to baseline file: {args.write_baseline}"
        )
        return 0

    reported = _emit_report(_apply_baseline(findings, args.baseline), args)
    return 3 if args.fail_on_findings and reported else 0


async def _scan_org(args: argparse.Namespace) -> int:
    async with GitHubClient() as github_client:
        scanner = RepositoryScanner(github_client, **_detector_kwargs(args))
        exclude_patterns = parse_exclude_patterns(args.exclude)
        result = await scanner.scan_org(
            args.org,
            branch=args.branch,
            exclude_patterns=exclude_patterns,
        )

        if args.include_history:
            history_result = await scanner.scan_org_history(
                args.org,
                branch=args.branch,
                max_commits=args.max_commits,
                exclude_patterns=exclude_patterns,
            )
            result = OrganizationScanResult(
                findings=result.findings + history_result.findings,
                failures=result.failures + history_result.failures,
            )

    if args.write_baseline is not None:
        write_baseline(args.write_baseline, result.findings)
        print(
            f"Wrote {len(result.findings)} finding(s) to baseline file: "
            f"{args.write_baseline}"
        )
        _emit_scan_failures(result)
        return 2 if result.failures else 0

    reported = _emit_report(_apply_baseline(result.findings, args.baseline), args)
    _emit_scan_failures(result)
    if result.failures:
        return 2
    return 3 if args.fail_on_findings and reported else 0


async def _scan_local(args: argparse.Namespace) -> int:
    scanner = LocalScanner(**_detector_kwargs(args))
    findings = scanner.scan_path(
        args.path,
        exclude_patterns=parse_exclude_patterns(args.exclude),
    )

    if args.write_baseline is not None:
        write_baseline(args.write_baseline, findings)
        print(
            f"Wrote {len(findings)} finding(s) to baseline file: {args.write_baseline}"
        )
        return 0

    reported = _emit_report(_apply_baseline(findings, args.baseline), args)
    return 3 if args.fail_on_findings and reported else 0


def _detector_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    """Build optional detector overrides so default scans stay untouched.

    Returning an empty dict when no override is requested keeps the scanner
    constructors on their default code path (and keeps test doubles that only
    accept the required positional argument working).
    """
    threshold = getattr(args, "entropy_threshold", None)
    if threshold is None:
        return {}
    if threshold <= 0:
        raise ValueError("--entropy-threshold must be greater than 0")

    hex_threshold = threshold * (
        DEFAULT_HEX_ENTROPY_THRESHOLD / DEFAULT_ENTROPY_THRESHOLD
    )
    return {
        "entropy_detector": EntropyDetector(
            entropy_threshold=threshold,
            hex_entropy_threshold=hex_threshold,
        )
    }


def _apply_baseline(
    findings: list[Finding], baseline_path: Path | None
) -> list[Finding]:
    if baseline_path is None:
        return findings

    accepted = load_baseline(baseline_path)
    return filter_accepted_findings(findings, accepted)


def _emit_report(findings: list[Finding], args: argparse.Namespace) -> list[Finding]:
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
    return filtered_findings


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
    if value in {"terminal", "json", "html", "sarif"}:
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
