# Secret Scanner CLI

A Python CLI for scanning public GitHub repositories for exposed secrets using
regex pattern matching and Shannon entropy analysis.

> Status: Phase 1 is implemented. The regex and entropy detectors are covered
> by unit tests. GitHub API scanning and CLI commands are planned next.

## Features

- Regex-based detection from external `patterns.yaml` definitions.
- Shannon entropy detection for high-entropy token-like strings.
- Typed findings with dataclasses.
- Secret redaction before values leave the detector layer.
- Unit tests for detector behavior and common false-positive filters.

## Planned CLI

```bash
secret-scanner scan repo owner/repo
secret-scanner scan org organization-name
```

Planned flags include `--branch`, `--exclude`, `--output json|html`, and
`--severity`.

## Development

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -e ".[dev]"
python -m pytest
```

## Project Layout

```text
secret-scanner-cli/
├── src/
│   └── secret_scanner/
│       ├── detectors/
│       ├── models.py
│       └── patterns.yaml
├── tests/
├── LEGAL.md
├── LICENSE
├── README.md
└── pyproject.toml
```

## Roadmap

- Async GitHub REST API client with pagination and rate-limit handling.
- Repository and organization scanning orchestration.
- Click-based CLI.
- Terminal, JSON, and HTML reports.
- Severity filtering and path exclusion.

## Legal

Use this tool only on repositories you own or are explicitly authorized to test.
See [LEGAL.md](LEGAL.md).

