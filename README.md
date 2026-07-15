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

A Python CLI that scans GitHub repositories for exposed secrets over the
GitHub API, without cloning them, using regex pattern matching and Shannon
entropy analysis. It also scans a local checkout, emits SARIF for GitHub code
scanning, and ships as a reusable GitHub Action.

Most secret scanners work on a local clone. Scanning over the API instead lets
you audit an entire organization, or a repository's commit history, without
pulling anything to disk first.

<p align="center">
  <img src="docs/assets/demo.gif" alt="Terminal recording of a local scan finding four secrets" width="820">
</p>

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

- Regex-based detection from external `patterns.yaml` definitions, covering 24
  providers (AWS access and secret keys, GitHub, GitLab, Stripe, Anthropic,
  OpenAI, Hugging Face, Google, Slack, Azure, and more).
- Shannon entropy detection for high-entropy token-like strings, with a
  charset-aware threshold so hexadecimal secrets are detectable, not just
  base64-class ones.
- Inline `# secret-scanner:ignore` / `pragma: allowlist secret` directives to
  silence a specific line without a baseline entry.
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
pip install cardesa-secret-scanner
```

The distribution is named `cardesa-secret-scanner` on PyPI; the installed
command is `secret-scanner`. For a local development checkout instead, see
[Development](#development).

## Usage

```bash
secret-scanner scan repo owner/repo
secret-scanner scan repo owner/repo --branch develop
secret-scanner scan repo owner/repo --exclude "*.min.js,package-lock.json"
secret-scanner scan repo owner/repo --severity high
secret-scanner scan repo owner/repo --entropy-threshold 4.0
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

For a single `scan repo` without `--branch`, the scanner looks up and uses the
repository's GitHub `default_branch`, so it works against repositories whose
default is `master`, `trunk`, or anything else, not just `main`. For
organization scans, each repository likewise uses its own `default_branch`
unless `--branch` is provided. If one repository fails, the scanner records the failure,
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

### Suppressing a single line

For a one-off false positive, an inline comment is lighter than a baseline
entry. Any line containing `secret-scanner:ignore`, `secret-scanner:allow`, or
`pragma: allowlist secret` (case-insensitive, in any comment syntax) is skipped
by both detectors:

```python
TEST_FIXTURE_KEY = "AKIAIOSFODNN7EXAMPLE"  # secret-scanner:ignore
```

### Tuning entropy noise

The entropy detector uses a charset-aware floor: base64-class tokens must clear
`--entropy-threshold` (default `4.5`), while hexadecimal-only tokens use a
proportionally lower floor so they are detectable at all (a hex string peaks at
4.0 bits/char and could never clear 4.5). Lower `--entropy-threshold` to catch
more, raise it to cut noise.

### Pre-commit hook

This repository exposes a [pre-commit](https://pre-commit.com) hook that runs
`scan local .` before each commit. Add it to a `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/JuanCardesa/secret-scanner-cli
    rev: develop
    hooks:
      - id: secret-scanner
```

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
Confidence | Method  | Pattern                      | Repository         | File    | Line | Entropy | Match
-----------+---------+------------------------------+--------------------+---------+------+---------+-------------------------------------------------
high       | regex   | AWS access key               | demo/local-fixture | app.env | 2    | 1.02    | AKIA************0000
high       | regex   | GitHub personal access token | demo/local-fixture | app.env | 3    | 0.67    | ghp_AAAA************************AAAAAAAA
high       | regex   | Stripe live API key          | demo/local-fixture | app.env | 4    | 1.50    | sk_liv********************BBBBBB
medium     | entropy | High entropy token           | demo/local-fixture | app.env | 5    | 4.79    | UvQXUNYAU******************************5ObQ3DfNB

4 potential secrets found.
```

JSON excerpt:

```json
{
  "confidence": "high",
  "detection_method": "regex",
  "entropy_score": 1.0219280948873624,
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

## CI/CD integration

This repository is itself a reusable composite GitHub Action
([action.yml](action.yml)) that installs the CLI and runs it for you. It
scans, writes a SARIF report, uploads it to GitHub code scanning, and fails
the job if findings remain (configurable):

```yaml
permissions:
  contents: read
  security-events: write # required for the SARIF upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: JuanCardesa/secret-scanner-cli@v0.1.0
        with:
          target-type: repo # 'local', 'repo', or 'org'
          target: owner/repo
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-findings: "true"
```

For `target-type: local`, no `github-token` is needed. See
[action.yml](action.yml) for every input (`branch`, `exclude`, `severity`,
`include-history`, `max-commits`, `baseline`, `sarif-path`).

[.github/workflows/secret-scan.yml](.github/workflows/secret-scan.yml) wires
this action up against this repository's own checkout on every push and
pull request, using `--baseline .secretscanner-baseline.json` to accept the
synthetic secret-shaped values that the test suite intentionally contains.
If you add a new fixture that looks like a real credential, regenerate that
baseline locally before pushing:

```bash
secret-scanner scan local . --write-baseline .secretscanner-baseline.json
```

## Project Layout

```text
secret-scanner-cli/
|-- .github/
|   `-- workflows/
|       |-- ci.yml
|       |-- release.yml
|       `-- secret-scan.yml
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
|       |-- baseline.py
|       |-- cli.py
|       |-- directives.py
|       |-- github_client.py
|       |-- local_scanner.py
|       |-- models.py
|       |-- reporter.py
|       |-- scanner.py
|       |-- patterns.yaml
|       `-- __main__.py
|-- tests/
|-- .env.example
|-- .pre-commit-hooks.yaml
|-- .secretscanner-baseline.json
|-- action.yml
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
- **Non-UTF-8 files are skipped silently.** Blobs and local files that do not
  decode as UTF-8 (including binaries, but also Latin-1 or UTF-16 source) are
  dropped rather than transcoded, so a secret living only in such a file is a
  false negative. Text in UTF-8 -- the overwhelming default for source and
  config -- is unaffected.
- **Entropy on hex is inherently noisy.** Charset-aware thresholds make
  hexadecimal secrets detectable, but a random 40-char commit SHA or a
  content hash is indistinguishable from a hex secret by shape alone and will
  be flagged. Lockfiles and the tool's own baseline are excluded by default;
  beyond that, use `--exclude`, the baseline, or inline directives to manage
  the noise, or raise `--entropy-threshold`.
- **The baseline allowlist is not centrally managed.** `--baseline` /
  `--write-baseline` (see [Usage](#usage)) work per invocation; there is no
  shared, versioned baseline store for a team, and a baseline file is only
  as trustworthy as the review behind the scan that produced it.
- **Regex coverage is broad but not exhaustive.** `patterns.yaml` covers the
  most common providers (see [Features](#features)) but, unlike dedicated
  projects such as `gitleaks` or `trufflehog`, it has not been validated
  against a catalog the size of `mazen160/secrets-patterns-db`.

## Roadmap

- Point `action.yml` at the published PyPI package. It currently installs
  from the action checkout on every run, which keeps the action code and the
  ref you pin exactly in sync; pinning a released version is a possible future
  optimization.
- Add a shared, versioned baseline workflow for teams (today, `--baseline`
  is a local file per invocation; see Limitations above).
- Grow `patterns.yaml` coverage toward a larger validated catalog.

## Legal

Use this tool only on repositories you own or are explicitly authorized to test.
See [LEGAL.md](LEGAL.md).
