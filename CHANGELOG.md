# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-15

First published release (distributed on PyPI as `cardesa-secret-scanner`).

### Added

- Regex-based secret detection from external `patterns.yaml`, covering 24
  providers (AWS access and secret keys, GitHub, GitLab, Stripe, Anthropic,
  OpenAI, Hugging Face, Google, Slack, Azure, and more), with a
  `(?P<secret>...)` named group to narrow context-anchored matches.
- Shannon entropy detection with charset-aware thresholds so hexadecimal
  secrets are detectable, tunable via `--entropy-threshold`, with noise
  suppression for dotted namespace paths, vendored/test/fixture trees, and
  bulk data or certificate files.
- Redacted, typed findings for detector output.
- Async GitHub REST API client with token authentication, pagination,
  rate-limit backoff, and safe blob decoding.
- Repository and organization scanning for public or authorized repositories,
  with partial-failure reporting for organization scans and `default_branch`
  resolution when `--branch` is omitted.
- Commit-history scanning (`--include-history`) that reconstructs a diff's
  added lines to catch secrets removed from the current tree.
- Local filesystem scanning (`scan local`) with no network access, plus a
  `.pre-commit-hooks.yaml` so it can run as a pre-commit hook.
- Baseline allowlist (`--baseline` / `--write-baseline`) keyed by stable
  fingerprints, and inline `secret-scanner:ignore` / `pragma: allowlist secret`
  suppression directives.
- Terminal, JSON, HTML, and SARIF 2.1.0 report output, `--severity` filtering,
  and `--fail-on-findings` CI gating.
- `--version` flag and `python -m secret_scanner` entry point.
- Reusable composite GitHub Action (`action.yml`) and tag-triggered PyPI
  release workflow via Trusted Publishing.
- CI checks for linting, formatting, typing, tests, and coverage; security,
  legal, contribution, and architecture documentation.

### Security

- Redact detected secret values before they leave the detector layer.
- Keep all GitHub HTTP access centralized in `github_client.py`.
- Pass GitHub Action inputs through the environment instead of interpolating
  them into the shell step, closing a command-injection vector.
- Avoid real GitHub API calls in the test suite.
