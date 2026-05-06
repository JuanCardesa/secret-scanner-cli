"""Report rendering for scanner findings."""

from __future__ import annotations

import html
import json
from dataclasses import asdict
from typing import Literal

from secret_scanner.models import Confidence, Finding

OutputFormat = Literal["terminal", "json", "html"]

CONFIDENCE_ORDER: dict[Confidence, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
}

CONFIDENCE_COLORS: dict[Confidence, str] = {
    "high": "31",
    "medium": "33",
    "low": "36",
}


def filter_findings_by_severity(
    findings: list[Finding],
    severity: Confidence | None,
) -> list[Finding]:
    """Return findings at or above the requested confidence level."""
    if severity is None:
        return findings

    minimum = CONFIDENCE_ORDER[severity]
    return [
        finding
        for finding in findings
        if CONFIDENCE_ORDER[finding.confidence] >= minimum
    ]


def render_report(
    findings: list[Finding],
    *,
    output_format: OutputFormat = "terminal",
    use_color: bool = True,
) -> str:
    if output_format == "terminal":
        return render_terminal(findings, use_color=use_color)
    if output_format == "json":
        return render_json(findings)
    if output_format == "html":
        return render_html(findings)

    raise ValueError(f"unsupported output format: {output_format}")


def render_json(findings: list[Finding]) -> str:
    report = {"findings": [asdict(finding) for finding in findings]}
    return json.dumps(report, indent=2, sort_keys=True)


def render_html(findings: list[Finding]) -> str:
    rows = "\n".join(_html_row(finding) for finding in findings)
    if not rows:
        rows = '<tr><td colspan="8">No findings detected.</td></tr>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secret Scanner CLI Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #172033; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #d6dbe3; padding: 0.5rem; text-align: left; }}
    th {{ background: #f3f6fa; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
  </style>
</head>
<body>
  <h1>Secret Scanner CLI Report</h1>
  <table>
    <thead>
      <tr>
        <th>Confidence</th>
        <th>Method</th>
        <th>Pattern</th>
        <th>Repository</th>
        <th>File</th>
        <th>Line</th>
        <th>Match</th>
        <th>Commit</th>
      </tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
</body>
</html>"""


def render_terminal(findings: list[Finding], *, use_color: bool = True) -> str:
    if not findings:
        return "No findings detected."

    headers = (
        "Confidence",
        "Method",
        "Pattern",
        "Repository",
        "File",
        "Line",
        "Match",
    )
    rows = [
        (
            finding.confidence,
            finding.detection_method,
            finding.pattern_name,
            finding.repo,
            finding.file_path,
            str(finding.line_number),
            finding.matched_text,
        )
        for finding in findings
    ]
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]

    lines = [
        _format_row(headers, widths),
        _format_separator(widths),
    ]
    for row, finding in zip(rows, findings, strict=True):
        lines.append(
            _format_row(
                row,
                widths,
                confidence=finding.confidence,
                use_color=use_color,
            )
        )

    return "\n".join(lines)


def _format_row(
    values: tuple[str, ...],
    widths: list[int],
    *,
    confidence: Confidence | None = None,
    use_color: bool = False,
) -> str:
    cells = [value.ljust(widths[index]) for index, value in enumerate(values)]
    if confidence is not None and use_color:
        cells[0] = _colorize(cells[0], CONFIDENCE_COLORS[confidence])

    return " | ".join(cells)


def _format_separator(widths: list[int]) -> str:
    return "-+-".join("-" * width for width in widths)


def _colorize(value: str, color_code: str) -> str:
    return f"\033[{color_code}m{value}\033[0m"


def _html_row(finding: Finding) -> str:
    return (
        "      <tr>"
        f"<td>{html.escape(finding.confidence)}</td>"
        f"<td>{html.escape(finding.detection_method)}</td>"
        f"<td>{html.escape(finding.pattern_name)}</td>"
        f"<td>{html.escape(finding.repo)}</td>"
        f"<td>{html.escape(finding.file_path)}</td>"
        f"<td>{finding.line_number}</td>"
        f"<td><code>{html.escape(finding.matched_text)}</code></td>"
        f"<td><code>{html.escape(finding.commit_sha)}</code></td>"
        "</tr>"
    )
