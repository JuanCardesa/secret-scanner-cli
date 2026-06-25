from __future__ import annotations

import json

from secret_scanner.models import Confidence, Finding
from secret_scanner.reporter import (
    filter_findings_by_severity,
    render_html,
    render_json,
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


def test_filter_findings_by_severity_uses_minimum_confidence() -> None:
    findings = [
        finding(confidence="low"),
        finding(confidence="medium"),
        finding(confidence="high"),
    ]

    filtered = filter_findings_by_severity(findings, "medium")

    assert [item.confidence for item in filtered] == ["medium", "high"]
