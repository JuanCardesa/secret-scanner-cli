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

> Status: Phases 1 to 4 are implemented. The project currently supports
> detector execution, GitHub API access, repository scan orchestration, terminal
> reports, JSON reports, HTML reports, and a tested `scan repo` CLI command.

## Features

- Regex-based detection from external `patterns.yaml` definitions.
- Shannon entropy detection for high-entropy token-like strings.
- Typed findings with dataclasses.
- Secret redaction before values leave the detector layer.
- Unit tests for detector behavior and common false-positive filters.
- Async GitHub REST API client with token auth, pagination, rate-limit backoff,
  and safe blob decoding.
- Repository scan orchestration with bounded blob-fetch concurrency.
- CLI command for scanning a single GitHub repository.
- Terminal, JSON, and HTML report rendering.
- Confidence filtering with `--severity`.

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
```

The default output is a colored terminal table. JSON and HTML reports can be
written to a file with `--output-file`.

## Development

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest
```

## Configuration

The GitHub client reads `GITHUB_TOKEN` from the environment when available.
Copy `.env.example` to `.env` for local development and keep `.env` out of Git.
Use a token that belongs to you and only scan repositories you are authorized to
audit.

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
|-- LEGAL.md
|-- LICENSE
|-- README.md
`-- pyproject.toml
```

## Roadmap

- Organization scanning with paginated public repository discovery.
- CLI support for `scan org`.
- Optional coverage reporting in CI.
- Architecture notes in `docs/architecture.md` as the scanner grows.

## Legal

Use this tool only on repositories you own or are explicitly authorized to test.
See [LEGAL.md](LEGAL.md).
