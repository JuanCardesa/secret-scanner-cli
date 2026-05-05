"""Shared typed models for detector output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Confidence = Literal["high", "medium", "low"]
DetectionMethod = Literal["regex", "entropy"]


@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: str
    confidence: Confidence
    example: str


@dataclass(frozen=True)
class Finding:
    repo: str
    file_path: str
    line_number: int
    matched_text: str
    detection_method: DetectionMethod
    pattern_name: str
    confidence: Confidence
    commit_sha: str
    author_email: str


def redact_secret(value: str) -> str:
    """Redact the middle 60% of a secret-like value."""
    if not value:
        return value

    length = len(value)
    if length <= 4:
        return "*" * length

    keep_each_side = max(1, int(length * 0.2))
    redacted_count = max(1, length - (keep_each_side * 2))
    return f"{value[:keep_each_side]}{'*' * redacted_count}{value[-keep_each_side:]}"

