# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-07

### Added

- Regex-based secret detection from external `patterns.yaml` definitions.
- Shannon entropy detection for high-entropy token-like values.
- Redacted, typed findings for detector output.
- Async GitHub REST API client with token authentication, pagination,
  rate-limit backoff, and safe blob decoding.
- Repository scanning for public or authorized GitHub repositories.
- Organization scanning across public repositories with partial-failure
  reporting.
- Terminal, JSON, and HTML report output.
- CLI options for branch selection, exclude patterns, confidence filtering,
  output format, output files, and color control.
- CI checks for linting, formatting, typing, tests, and coverage.
- Security, legal, contribution, and architecture documentation.

### Fixed

- Create parent directories automatically when writing reports with
  `--output-file`.

### Security

- Redact detected secret values before they leave the detector layer.
- Keep all GitHub HTTP access centralized in `github_client.py`.
- Avoid real GitHub API calls in the test suite.
