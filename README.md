<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/secret-scanner-cli-logo-dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/secret-scanner-cli-logo-light.png">
    <img src="docs/assets/secret-scanner-cli-logo-light.png" alt="Secret Scanner CLI logo" width="360">
  </picture>

  <h1>Secret Scanner CLI</h1>

  <p>Defensive Python CLI for authorized GitHub secret scanning.</p>

  <p>
    <a href="https://github.com/JuanCardesa/secret-scanner-cli/actions/workflows/ci.yml">
      <img src="https://github.com/JuanCardesa/secret-scanner-cli/actions/workflows/ci.yml/badge.svg?branch=develop" alt="CI">
    </a>
  </p>
</div>

A Python CLI for scanning public GitHub repositories for exposed secrets using
regex pattern matching and Shannon entropy analysis.

> Status: Phases 1 to 5 are implemented. The project currently supports
> detector execution, GitHub API access, repository scan orchestration, terminal
> reports, JSON reports, HTML reports, and tested `scan repo` / `scan org`
> commands.

## Features

- Regex-based detection from external `patterns.yaml` definitions.
- Shannon entropy detection for high-entropy token-like strings.
- Typed findings with dataclasses.
- Secret redaction before values leave the detector layer.
- Unit tests for detector behavior and common false-positive filters.
- Async GitHub REST API client with token auth, pagination, rate-limit backoff,
  and safe blob decoding.
- Repository scan orchestration with bounded blob-fetch and repo concurrency.
- CLI commands for scanning a single GitHub repository or all public repos in an
  organization.
- Terminal, JSON, and HTML report rendering.
- Confidence filtering with `--severity`.
- CI checks for linting, formatting, static typing, tests, and coverage.

## Installation

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Usage

```bash
secret-scanner scan repo owner/repo
secret-scanner scan repo owner/repo --branch develop
secret-scanner scan repo owner/repo --exclude "*.min.js,package-lock.json"
secret-scanner scan repo owner/repo --severity high
secret-scanner scan repo owner/repo --output json --output-file reports/report.json
secret-scanner scan repo owner/repo --output html --output-file reports/report.html
secret-scanner scan org organization-name
secret-scanner scan org organization-name --branch release
secret-scanner scan org organization-name --severity high --output json
```

The default output is a colored terminal table. JSON and HTML reports can be
written to a file with `--output-file`.

For organization scans, each repository uses its GitHub `default_branch` unless
`--branch` is provided. If one repository fails, the scanner records the failure,
continues with the remaining repositories, prints a warning to stderr, and exits
with status code `2` to signal a partial scan.

## Development

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch, commit, and pull request
workflow.

## Configuration

The GitHub client reads `GITHUB_TOKEN` from the environment when available.
Copy `.env.example` to `.env` for local development and keep `.env` out of Git.
Use a token that belongs to you and only scan repositories or organizations you
are authorized to audit.

## Project Layout

```text
secret-scanner-cli/
|-- .github/
|   `-- workflows/
|       `-- ci.yml
|-- docs/
|   `-- assets/
|       |-- secret-scanner-cli-logo-dark.png
|       `-- secret-scanner-cli-logo-light.png
|   `-- architecture.md
|-- src/
|   `-- secret_scanner/
|       |-- detectors/
|       |-- cli.py
|       |-- github_client.py
|       |-- models.py
|       |-- reporter.py
|       |-- scanner.py
|       `-- patterns.yaml
|-- tests/
|-- .env.example
|-- CONTRIBUTING.md
|-- LEGAL.md
|-- LICENSE
|-- README.md
|-- SECURITY.md
`-- pyproject.toml
```

See [docs/architecture.md](docs/architecture.md) for a summary of the main
components and security boundaries.

## Roadmap

- Release preparation for `v0.1.0`.
- Changelog maintenance for future releases.

## Legal

Use this tool only on repositories you own or are explicitly authorized to test.
See [LEGAL.md](LEGAL.md).
