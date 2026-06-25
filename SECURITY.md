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

## Responsible Disclosure for Secrets Found With This Tool

This section covers what to do if `secret-scanner` finds a real, live secret
in a repository you are authorized to scan but do not own (for example, a
client engagement or a bug bounty target). It does not cover bugs in the
scanner itself; for that, see "Reporting a Vulnerability" above.

1. **Stop. Do not use the credential.** Do not authenticate with it, do not
   query the provider it belongs to beyond confirming the finding is not an
   obvious false positive, and do not download or exfiltrate any data it
   would grant access to.
2. **Do not commit, push, or publish the unredacted secret anywhere**,
   including in the scanner's own output, issue trackers, chat tools, or
   bug bounty report drafts. Redact it the same way this project's own
   reports do (`AKIA************0000`) when discussing the finding.
3. **Report it through the repository or organization owner's published
   channel**: their `SECURITY.md`, a `security.txt` file, GitHub's private
   vulnerability reporting feature on that repository, or their bug bounty
   program if one exists. Include the repository, file path, and commit
   (the scanner's report gives you all three), but not the secret value.
4. **Give the owner a reasonable, industry-standard window to rotate the
   credential and respond** before discussing the finding publicly, in line
   with common coordinated-disclosure norms (commonly 90 days, or whatever
   the owner's own policy specifies).
5. **If you cannot identify an owner or contact channel**, GitHub Support
   accepts reports of exposed credentials directly.

This project has so far only been run against synthetic, locally generated
fixtures and intentionally vulnerable public test repositories such as
[`trufflesecurity/test_keys`](https://github.com/trufflesecurity/test_keys) --
it has not yet been used to disclose a real-world leak. That is a deliberate
choice while the detector logic and history scanning were still actively
changing: running it against third-party repositories before the
false-positive rate and redaction behavior were trustworthy risked both
noisy, low-credibility reports and mishandling a real credential. The steps
above are the process this project will follow once it is used against real
targets.

## Handling Sensitive Data

Detected values must remain redacted before being printed, serialized, logged,
or rendered in reports. Tests should use synthetic fixtures only.

The `GITHUB_TOKEN` environment variable is used only for authenticated GitHub API
requests initiated by the user. It must not be logged, printed, exported, or
written to reports.
