"""Baseline allowlist for previously accepted findings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from secret_scanner.models import Finding


class BaselineError(ValueError):
    """Raised when a baseline file cannot be loaded or is malformed."""


def finding_fingerprint(finding: Finding) -> str:
    """Return a stable identifier for a finding's location and value.

    Deliberately excludes commit_sha. For a tree scan, the latest commit
    changes on every unrelated push, which would silently break baseline
    matching for a secret that never moved. For a history scan, the same
    secret value repeated across commits should collapse to one baseline
    entry rather than one per commit.
    """
    raw = "\x1f".join(
        (
            finding.repo,
            finding.file_path,
            str(finding.line_number),
            finding.detection_method,
            finding.pattern_name,
            finding.matched_text,
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_baseline(path: str | Path) -> set[str]:
    """Load accepted fingerprints from a baseline file."""
    baseline_path = Path(path)
    if not baseline_path.is_file():
        raise BaselineError(f"baseline file not found: {baseline_path}")

    try:
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"baseline file is not valid JSON: {baseline_path}"
        ) from exc

    entries = payload.get("accepted") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        raise BaselineError(
            f"baseline file must contain an 'accepted' list: {baseline_path}"
        )

    fingerprints: set[str] = set()
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str):
            fingerprints.add(entry["fingerprint"])

    return fingerprints


def filter_accepted_findings(
    findings: list[Finding],
    accepted_fingerprints: set[str],
) -> list[Finding]:
    """Return findings whose fingerprint is not in the accepted set."""
    return [
        finding
        for finding in findings
        if finding_fingerprint(finding) not in accepted_fingerprints
    ]


def write_baseline(path: str | Path, findings: list[Finding]) -> None:
    """Write every finding from this scan to PATH as an accepted baseline."""
    baseline_path = Path(path)
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    by_fingerprint: dict[str, Finding] = {}
    for finding in findings:
        by_fingerprint.setdefault(finding_fingerprint(finding), finding)

    payload = {
        "accepted": [
            {
                "fingerprint": fingerprint,
                "repo": finding.repo,
                "file_path": finding.file_path,
                "pattern_name": finding.pattern_name,
            }
            for fingerprint, finding in sorted(by_fingerprint.items())
        ]
    }
    baseline_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
