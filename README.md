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

## Example Results

The repository includes a local demo that scans a controlled synthetic fixture.
The fixture is generated at runtime under `docs/demo/.generated/`, which is
ignored by Git. It contains only fake values created for scanner validation, and
the committed demo reports contain only redacted matches.

Regenerate the demo reports locally:

```bash
python docs/demo/generate_example_results.py
```

The command writes:

- terminal output: [docs/demo/reports/example-terminal.txt](docs/demo/reports/example-terminal.txt)
- JSON report: [docs/demo/reports/example-report.json](docs/demo/reports/example-report.json)
- HTML report: [docs/demo/reports/example-report.html](docs/demo/reports/example-report.html)

The demo fixture produces four findings: three high-confidence regex matches
for AWS, GitHub, and Stripe-shaped values, plus one medium-confidence entropy
match for a generated token-like value.

Terminal excerpt:

```text
Confidence | Method  | Pattern                      | Repository         | File    | Line | Match
-----------+---------+------------------------------+--------------------+---------+------+-------------------------------------------------
high       | regex   | AWS access key               | demo/local-fixture | app.env | 2    | AKIA************0000
high       | regex   | GitHub personal access token | demo/local-fixture | app.env | 3    | ghp_AAAA************************AAAAAAAA
high       | regex   | Stripe live API key          | demo/local-fixture | app.env | 4    | sk_liv********************BBBBBB
medium     | entropy | High entropy token           | demo/local-fixture | app.env | 5    | UvQXUNYAU******************************5ObQ3DfNB
```

JSON excerpt:

```json
{
  "confidence": "high",
  "detection_method": "regex",
  "file_path": "app.env",
  "matched_text": "AKIA************0000",
  "pattern_name": "AWS access key",
  "repo": "demo/local-fixture"
}
```

HTML excerpt:

```html
<tr><td>medium</td><td>entropy</td><td>High entropy token</td><td>demo/local-fixture</td><td>app.env</td><td>5</td><td><code>UvQXUNYAU******************************5ObQ3DfNB</code></td><td><code>demo-local-commit</code></td></tr>
```

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
|   |-- assets/
|   |   |-- secret-scanner-cli-logo-dark.png
|   |   `-- secret-scanner-cli-logo-light.png
|   |-- demo/
|   |   |-- generate_example_results.py
|   |   `-- reports/
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

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## Roadmap

- Publish the `v0.1.0` release.
- Add release automation for future versions.

## Legal

Use this tool only on repositories you own or are explicitly authorized to test.
See [LEGAL.md](LEGAL.md).
