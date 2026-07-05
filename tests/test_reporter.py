from __future__ import annotations

import json

from secret_scanner.baseline import finding_fingerprint
from secret_scanner.models import Confidence, Finding
from secret_scanner.reporter import (
    filter_findings_by_severity,
    render_html,
    render_json,
    render_report,
    render_sarif,
    render_terminal,
)


def finding(
    *,
    confidence: Confidence = "high",
    matched_text: str = "AKIA************ABCD",
) -> Finding:
    return Finding(
        repo="example/repo",
        file_path="config/settings.env",
        line_number=12,
        matched_text=matched_text,
        detection_method="regex",
        pattern_name="AWS Access Key ID",
        confidence=confidence,
        commit_sha="abc123",
    )


def test_render_json_returns_structured_report() -> None:
    report = json.loads(render_json([finding()]))

    assert report == {
        "findings": [
            {
                "repo": "example/repo",
                "file_path": "config/settings.env",
                "line_number": 12,
                "matched_text": "AKIA************ABCD",
                "detection_method": "regex",
                "pattern_name": "AWS Access Key ID",
                "confidence": "high",
                "commit_sha": "abc123",
                "entropy_score": 0.0,
            }
        ]
    }


def test_render_terminal_uses_redacted_values() -> None:
    output = render_terminal([finding()], use_color=False)
    unredacted_value = "AKIA" + ("0" * 12) + "ABCD"

    assert "Confidence" in output
    assert "AWS Access Key ID" in output
    assert "AKIA************ABCD" in output
    assert unredacted_value not in output


def test_render_terminal_handles_empty_findings() -> None:
    assert render_terminal([], use_color=False) == "No findings detected."


def test_render_html_escapes_finding_values() -> None:
    output = render_html(
        [
            finding(
                matched_text="<script>alert('redacted')</script>",
            )
        ]
    )

    assert "&lt;script&gt;" in output
    assert "<script>alert" not in output


def test_render_sarif_produces_valid_structure_with_fingerprint() -> None:
    report = json.loads(render_sarif([finding()]))

    assert report["version"] == "2.1.0"
    run = report["runs"][0]
    assert run["tool"]["driver"]["name"] == "secret-scanner"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "aws-access-key-id-regex"
    ]

    result = run["results"][0]
    assert result["ruleId"] == "aws-access-key-id-regex"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "config/settings.env"
    )
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert result["partialFingerprints"]["secretScannerFingerprint/v1"] == (
        finding_fingerprint(finding())
    )


def test_render_sarif_maps_confidence_to_level() -> None:
    report = json.loads(
        render_sarif([finding(confidence="medium"), finding(confidence="low")])
    )

    levels = [result["level"] for result in report["runs"][0]["results"]]
    assert levels == ["warning", "note"]


def test_render_sarif_deduplicates_rules_for_repeated_patterns() -> None:
    report = json.loads(render_sarif([finding(), finding(matched_text="different")]))

    assert len(report["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(report["runs"][0]["results"]) == 2


def test_render_sarif_handles_empty_findings() -> None:
    report = json.loads(render_sarif([]))

    assert report["runs"][0]["results"] == []
    assert report["runs"][0]["tool"]["driver"]["rules"] == []


def test_render_report_dispatches_to_sarif() -> None:
    output = render_report([finding()], output_format="sarif")

    assert json.loads(output)["version"] == "2.1.0"


def test_filter_findings_by_severity_uses_minimum_confidence() -> None:
    findings = [
        finding(confidence="low"),
        finding(confidence="medium"),
        finding(confidence="high"),
    ]

    filtered = filter_findings_by_severity(findings, "medium")

    assert [item.confidence for item in filtered] == ["medium", "high"]
