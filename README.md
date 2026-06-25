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

## Why this matters

Committing a secret to Git does not just expose it at `HEAD`: once it lands
in a commit, it stays reachable from that repository's history even after
the line is deleted in a later commit, unless the history itself is rewritten
and force-pushed. Public GitHub repositories are scraped continuously by
automated bots looking for exactly this pattern, and credential leaks
committed to source control have repeatedly led to real breaches at
companies of every size, not just hobby projects.

This is why `scan repo --include-history` walks commit diffs instead of only
the current tree (see [Usage](#usage)): a secret that was added in commit 3
and deleted in commit 7 is invisible to a scanner that only checks the
latest tree, but it is still sitting in the repository's history for anyone
to clone and inspect.

## Features

- Regex-based detection from external `patterns.yaml` definitions.
- Shannon entropy detection for high-entropy token-like strings.
- Typed findings with dataclasses.
- Secret redaction before values leave the detector layer.
- Unit tests for detector behavior and common false-positive filters.
- Async GitHub REST API client with token auth, pagination, rate-limit backoff,
  and safe blob decoding.
- Repository scan orchestration with bounded blob-fetch and repo concurrency.
- CLI commands for scanning a single GitHub repository, all public repos in an
  organization, or a local directory/file without any GitHub API access.
- Terminal, JSON, HTML, and SARIF 2.1.0 report rendering, the last for
  GitHub code scanning ingestion.
- Confidence filtering with `--severity` and CI gating with
  `--fail-on-findings`.
- Commit-history scanning with `--include-history` for both `scan repo` and
  `scan org`.
- Baseline allowlist (`--baseline` / `--write-baseline`) to suppress
  previously accepted findings.
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
secret-scanner scan repo owner/repo --include-history
secret-scanner scan repo owner/repo --include-history --max-commits 200
secret-scanner scan org organization-name
secret-scanner scan org organization-name --branch release
secret-scanner scan org organization-name --severity high --output json
secret-scanner scan org organization-name --include-history --max-commits 200
secret-scanner scan repo owner/repo --write-baseline baseline.json
secret-scanner scan repo owner/repo --baseline baseline.json
secret-scanner scan local .
secret-scanner scan local /path/to/checkout --exclude "*.min.js,dist/*"
secret-scanner scan local . --output json --output-file reports/local-report.json
secret-scanner scan local . --output sarif --output-file results.sarif
secret-scanner scan repo owner/repo --fail-on-findings
```

The default output is a colored terminal table. JSON, HTML, and SARIF
reports can be written to a file with `--output-file`. `--fail-on-findings`
exits with status code `3` if the report (after `--severity` and
`--baseline` filtering) is non-empty, which is what makes any of these
commands usable as a CI gate.

For organization scans, each repository uses its GitHub `default_branch` unless
`--branch` is provided. If one repository fails, the scanner records the failure,
continues with the remaining repositories, prints a warning to stderr, and exits
with status code `2` to signal a partial scan.

By default, `scan repo` and `scan org` only inspect the current tree at each
target branch's latest commit, so a secret that was committed and later
removed will not be found. Pass `--include-history` to additionally scan the
lines added by the most recent commits (50 by default, configurable with
`--max-commits`) on that branch, so secrets that only ever existed in
history are still caught. For `scan org`, `--max-commits` applies per
repository.

### Local scanning

`scan local PATH` walks a local directory or file directly -- no GitHub
API calls, no network access, no `GITHUB_TOKEN` required. It applies the
same regex and entropy detectors, the same `--exclude` patterns, and the
same `--severity`/`--baseline` handling as `scan repo`, which makes it
usable both as a one-off audit of a checkout you already have on disk and
as the entry point for a pre-commit hook (point it at the repository root
before every commit). `.git`, `node_modules`, virtual environments, and
common cache directories are always skipped, on top of whatever
`--exclude` patterns you pass. `--include-history` is not available here:
there is no API call to fetch commit diffs from, only the files on disk.

### Baseline allowlist

Every finding gets a stable fingerprint from its repository, file path, line
number, detection method, pattern, and redacted value (not its commit, so
the fingerprint survives unrelated commits to the branch). `--write-baseline
PATH` snapshots every finding from the current scan into a baseline file and
exits without printing a report; `--baseline PATH` loads that file on a
later scan and removes any finding matching an accepted fingerprint from the
report, so only new findings show up. Review a scan's output before writing
a baseline from it -- the baseline mechanism does not distinguish a real
secret from a false positive, it only remembers what you told it to accept.

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

## Limitations

- **`scan local` has no history mode.** It only walks whatever is on disk
  right now; it cannot inspect git history the way `scan repo
  --include-history` can, since that requires GitHub API calls to fetch
  commit diffs. Use `scan repo --include-history` against the same
  repository once it is pushed if you need that.
- **History scanning multiplies API calls per repository it covers.**
  `--include-history` on `scan org` runs commit-history scanning for every
  repository in the organization, which can be expensive in both API calls
  and rate-limit budget for large organizations; tune `--max-commits` down
  accordingly.
- **Very large trees and commits are not paginated.** GitHub truncates a
  recursive tree listing past a repository-size threshold, and a single
  commit's file list past roughly 300 changed files; the scanner currently
  refuses to scan a truncated tree rather than silently returning partial
  results, and does not yet paginate oversized commit file lists.
- **No live credential verification.** Unlike some scanners, this tool never
  attempts to use a detected key against the provider it belongs to. That is
  a deliberate choice to avoid making unauthorized requests with someone
  else's credentials, at the cost of being unable to confirm a key is still
  active.
- **The baseline allowlist is not centrally managed.** `--baseline` /
  `--write-baseline` (see [Usage](#usage)) work per invocation; there is no
  shared, versioned baseline store for a team, and a baseline file is only
  as trustworthy as the review behind the scan that produced it.
- **No packaged CI/CD integration yet.** SARIF output and `--fail-on-findings`
  give CI systems what they need to gate a build, but there is still no
  reusable GitHub Action; wiring this into a pull request check today means
  scripting the CLI install and invocation yourself.
- **Regex coverage is broad but not exhaustive.** `patterns.yaml` covers the
  most common providers (see [Features](#features)) but, unlike dedicated
  projects such as `gitleaks` or `trufflehog`, it has not been validated
  against a catalog the size of `mazen160/secrets-patterns-db`.

## Roadmap

- Publish the `v0.1.0` release.
- Add release automation for future versions.
- Add a reusable GitHub Action wrapping the CLI for CI integration.

## Legal

Use this tool only on repositories you own or are explicitly authorized to test.
See [LEGAL.md](LEGAL.md).
