# Architecture

Secret Scanner CLI is organized around a small set of boundaries. The goal is
to keep GitHub access, scan orchestration, detection, and reporting separate so
each piece can be tested without real network calls.

## Components

```text
CLI
 |
 +--> RepositoryScanner ---> GitHubClient        (repo / org, API-based)
 |        |
 +--> LocalScanner                               (filesystem, no network)
 |        |
 |        +--> RegexDetector
 |        +--> EntropyDetector
 |
 +--> baseline (fingerprint allowlist)
 |
 v
Reporter (terminal | json | html | sarif)
```

## GitHub Client

`github_client.py` is the only module that performs GitHub API requests. It
owns:

- authentication headers;
- GitHub API version headers;
- pagination;
- rate-limit backoff (shared across concurrent tasks via a lock);
- HTTP error normalization;
- safe base64 blob decoding.

Tests use `httpx.MockTransport` so CI never depends on live GitHub API calls.
A `sleep`/`clock` seam lets the rate-limit logic be tested without real delays.

## Scanners

`scanner.py` coordinates repository and organization scans over the API. It
resolves branch SHAs (looking up a repository's `default_branch` when the
caller omits `--branch`), loads recursive Git trees, skips excluded or oversized
files, fetches text blobs, and passes content to the detector layer. With
`--include-history` it also walks recent commit diffs and reconstructs a sparse
file from each diff's added lines, so a secret that was committed and later
removed is still found at its real line number.

Repository scans fail fast if GitHub returns a truncated tree, because scanning a
partial tree would create false negatives. Organization scans continue when one
repository fails and record the failed repository as a partial scan failure.

`local_scanner.py` runs the same detectors against a directory or file on disk
with no network access. It prunes noise directories (`.git`, `node_modules`,
virtualenvs, caches, `build`/`dist`) during the walk so it never descends into
them.

## Detectors

The detector layer is intentionally independent from GitHub:

- `regex_detector.py` loads external YAML patterns and returns typed findings.
  A `(?P<secret>...)` named group narrows the reported value to the credential
  when a pattern must anchor on surrounding context.
- `entropy_detector.py` flags high-entropy token-like strings using a
  charset-aware threshold (a lower floor for hex-only tokens), while avoiding
  common noisy files and generated content.
- `directives.py` provides the shared inline-suppression check
  (`secret-scanner:ignore`, `pragma: allowlist secret`) both detectors honor.

Detected values are redacted before they leave the detector layer.

## Baseline

`baseline.py` derives a stable SHA-256 fingerprint per finding from its
location, detection method, pattern, and redacted value (deliberately excluding
the commit SHA). `--write-baseline` snapshots findings; `--baseline` filters any
finding whose fingerprint was previously accepted, so only new findings surface.

## Reporting

`reporter.py` renders already-redacted findings as terminal, JSON, HTML, or
SARIF 2.1.0 reports. It does not fetch data, mutate findings, or print full
secrets. SARIF output is what makes the results ingestible by GitHub code
scanning.

## CLI

`cli.py` parses user input and wires together the GitHub client, scanners,
baseline, and reporter. Shared flags are defined once and attached to each
`scan repo | org | local` subcommand. Exit codes are meaningful: `0` clean,
`1` error, `2` partial org scan, `3` findings remain under `--fail-on-findings`.

## Security Principles

- All GitHub HTTP calls go through `GitHubClient`.
- Tests do not perform real network calls.
- Secrets are redacted before output.
- `GITHUB_TOKEN` is read from the environment and never printed.
- The tool is designed only for authorized defensive auditing.
