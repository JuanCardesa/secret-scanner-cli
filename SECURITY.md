# Security Policy

Secret Scanner CLI is intended for defensive, authorized repository auditing.
Use it only on repositories and organizations you own or are explicitly allowed
to assess.

## Supported Versions

This project is currently pre-release. Security fixes are applied to the
`develop` branch first and are included in the next stable release to `main`.

## Reporting a Vulnerability

If you find a security issue in the scanner itself, please open a private report
through GitHub's vulnerability reporting feature if available, or contact the
repository owner directly.

Do not include live credentials, private tokens, or unredacted secrets in issue
descriptions, pull requests, screenshots, logs, or example reports.

## Defensive Scope

The project accepts contributions that improve:

- secret detection accuracy;
- safe redaction;
- GitHub API reliability;
- test coverage;
- documentation;
- defensive scanning workflows.

The project does not accept contributions that add:

- credential theft or token exfiltration;
- exploit logic;
- authentication bypasses;
- unauthorized repository access;
- persistence, stealth, or evasion behavior;
- storage or transmission of full detected secrets.

## Handling Sensitive Data

Detected values must remain redacted before being printed, serialized, logged,
or rendered in reports. Tests should use synthetic fixtures only.

The `GITHUB_TOKEN` environment variable is used only for authenticated GitHub API
requests initiated by the user. It must not be logged, printed, exported, or
written to reports.
