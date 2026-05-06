# Architecture

Secret Scanner CLI is organized around a small set of boundaries. The goal is
to keep GitHub access, scan orchestration, detection, and reporting separate so
each piece can be tested without real network calls.

## Components

```text
CLI
 |
 v
RepositoryScanner
 |
 +--> GitHubClient
 |
 +--> RegexDetector
 |
 +--> EntropyDetector
 |
 v
Reporter
```

## GitHub Client

`github_client.py` is the only module that performs GitHub API requests. It
owns:

- authentication headers;
- GitHub API version headers;
- pagination;
- rate-limit backoff;
- HTTP error normalization;
- safe base64 blob decoding.

Tests use `httpx.MockTransport` so CI never depends on live GitHub API calls.

## Scanner

`scanner.py` coordinates repository and organization scans. It resolves branch
SHAs, loads recursive Git trees, skips excluded or oversized files, fetches text
blobs, and passes content to the detector layer.

Repository scans fail fast if GitHub returns a truncated tree, because scanning a
partial tree would create false negatives. Organization scans continue when one
repository fails and record the failed repository as a partial scan failure.

## Detectors

The detector layer is intentionally independent from GitHub:

- `regex_detector.py` loads external YAML patterns and returns typed findings.
- `entropy_detector.py` flags high-entropy token-like strings while avoiding
  common noisy files and generated content.

Detected values are redacted before they leave the detector layer.

## Reporting

`reporter.py` renders already-redacted findings as terminal, JSON, or HTML
reports. It does not fetch data, mutate findings, or print full secrets.

## CLI

`cli.py` parses user input and wires together the GitHub client, scanner, and
reporter. It supports:

- `secret-scanner scan repo owner/repo`;
- `secret-scanner scan org organization`;
- branch selection;
- exclude patterns;
- confidence filtering;
- terminal, JSON, and HTML output.

## Security Principles

- All GitHub HTTP calls go through `GitHubClient`.
- Tests do not perform real network calls.
- Secrets are redacted before output.
- `GITHUB_TOKEN` is read from the environment and never printed.
- The tool is designed only for authorized defensive auditing.
