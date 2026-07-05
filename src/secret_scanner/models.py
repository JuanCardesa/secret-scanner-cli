"""Shared typed models for detector output."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Literal

Confidence = Literal["high", "medium", "low"]
DetectionMethod = Literal["regex", "entropy"]


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy (bits per character) of a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


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
    entropy_score: float = 0.0


@dataclass(frozen=True)
class GitHubRepo:
    id: int
    name: str
    full_name: str
    default_branch: str
    html_url: str
    private: bool


@dataclass(frozen=True)
class GitTreeItem:
    path: str
    mode: str
    type: str
    sha: str
    size: int | None = None
    url: str | None = None


@dataclass(frozen=True)
class GitTree:
    sha: str
    tree: list[GitTreeItem]
    truncated: bool


@dataclass(frozen=True)
class CommitFile:
    filename: str
    status: str
    patch: str | None


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
