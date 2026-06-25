from __future__ import annotations

import json
from pathlib import Path

import pytest

from secret_scanner.baseline import (
    BaselineError,
    filter_accepted_findings,
    finding_fingerprint,
    load_baseline,
    write_baseline,
)
from secret_scanner.models import Finding


def finding(
    *,
    repo: str = "example/repo",
    file_path: str = "config/settings.env",
    line_number: int = 5,
    matched_text: str = "AKIA************ABCD",
    detection_method: str = "regex",
    pattern_name: str = "AWS access key",
    commit_sha: str = "abc123",
) -> Finding:
    return Finding(
        repo=repo,
        file_path=file_path,
        line_number=line_number,
        matched_text=matched_text,
        detection_method=detection_method,  # type: ignore[arg-type]
        pattern_name=pattern_name,
        confidence="high",
        commit_sha=commit_sha,
    )


def test_finding_fingerprint_ignores_commit_sha() -> None:
    first = finding(commit_sha="commit-1")
    second = finding(commit_sha="commit-2")

    assert finding_fingerprint(first) == finding_fingerprint(second)


def test_finding_fingerprint_differs_on_value_or_location() -> None:
    base = finding()

    assert finding_fingerprint(base) != finding_fingerprint(
        finding(matched_text="different")
    )
    assert finding_fingerprint(base) != finding_fingerprint(finding(line_number=99))
    assert finding_fingerprint(base) != finding_fingerprint(finding(repo="other/repo"))


def test_write_baseline_then_load_round_trips(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    findings = [finding(), finding(file_path="other.env", matched_text="different")]

    write_baseline(baseline_path, findings)
    accepted = load_baseline(baseline_path)

    assert accepted == {finding_fingerprint(f) for f in findings}


def test_write_baseline_deduplicates_repeated_fingerprints(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    same_finding = finding()

    write_baseline(baseline_path, [same_finding, same_finding, same_finding])

    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert len(payload["accepted"]) == 1


def test_write_baseline_creates_parent_directories(tmp_path: Path) -> None:
    baseline_path = tmp_path / "nested" / "baseline.json"

    write_baseline(baseline_path, [finding()])

    assert baseline_path.exists()


def test_filter_accepted_findings_excludes_matching_fingerprints() -> None:
    accepted_finding = finding()
    new_finding = finding(matched_text="brand-new-secret-value")
    accepted = {finding_fingerprint(accepted_finding)}

    remaining = filter_accepted_findings([accepted_finding, new_finding], accepted)

    assert remaining == [new_finding]


def test_load_baseline_rejects_missing_file(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match="not found"):
        load_baseline(tmp_path / "missing.json")


def test_load_baseline_rejects_invalid_json(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text("not json", encoding="utf-8")

    with pytest.raises(BaselineError, match="not valid JSON"):
        load_baseline(baseline_path)


def test_load_baseline_rejects_missing_accepted_key(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps({"foo": []}), encoding="utf-8")

    with pytest.raises(BaselineError, match="'accepted' list"):
        load_baseline(baseline_path)


def test_load_baseline_ignores_malformed_entries(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "accepted": [
                    "not-a-dict",
                    {"no_fingerprint": "x"},
                    {"fingerprint": "abc"},
                ]
            }
        ),
        encoding="utf-8",
    )

    assert load_baseline(baseline_path) == {"abc"}
