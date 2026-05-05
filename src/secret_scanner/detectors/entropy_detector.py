"""Shannon entropy-based secret detection."""

from __future__ import annotations

import fnmatch
import math
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Iterable

from secret_scanner.models import Finding, redact_secret

TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_./+=:-]{21,}(?![A-Za-z0-9])")
DEFAULT_ENTROPY_THRESHOLD = 4.5
DEFAULT_MIN_TOKEN_LENGTH = 21
DEFAULT_EXCLUDED_PATHS = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "*.min.js",
    "*.map",
)
IMAGE_EXTENSIONS = {".gif", ".jpg", ".jpeg", ".png", ".webp", ".ico", ".svg"}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class EntropyDetector:
    def __init__(
        self,
        *,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        min_token_length: int = DEFAULT_MIN_TOKEN_LENGTH,
        excluded_paths: Iterable[str] = DEFAULT_EXCLUDED_PATHS,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.min_token_length = min_token_length
        self.excluded_paths = tuple(excluded_paths)

    def scan(
        self,
        content: str,
        *,
        repo: str = "",
        file_path: str = "",
        commit_sha: str = "",
        author_email: str = "",
    ) -> list[Finding]:
        if self._is_excluded_file(file_path):
            return []

        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()

        for line_number, line in enumerate(content.splitlines(), start=1):
            if _is_false_positive_line(line):
                continue

            for match in TOKEN_RE.finditer(line):
                token = match.group(0).strip(".,;\"'`)]}>")
                if len(token) < self.min_token_length:
                    continue

                if shannon_entropy(token) <= self.entropy_threshold:
                    continue

                fingerprint = (line_number, token)
                if fingerprint in seen:
                    continue

                seen.add(fingerprint)
                findings.append(
                    Finding(
                        repo=repo,
                        file_path=file_path,
                        line_number=line_number,
                        matched_text=redact_secret(token),
                        detection_method="entropy",
                        pattern_name="High entropy token",
                        confidence="medium",
                        commit_sha=commit_sha,
                        author_email=author_email,
                    )
                )

        return findings

    def _is_excluded_file(self, file_path: str) -> bool:
        normalized = file_path.replace("\\", "/")
        name = PurePosixPath(normalized).name
        suffix = PurePosixPath(normalized).suffix.lower()

        if suffix in IMAGE_EXTENSIONS:
            return True

        return any(
            fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(name, pattern)
            for pattern in self.excluded_paths
        )


def scan_content(
    content: str,
    *,
    repo: str = "",
    file_path: str = "",
    commit_sha: str = "",
    author_email: str = "",
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    min_token_length: int = DEFAULT_MIN_TOKEN_LENGTH,
) -> list[Finding]:
    detector = EntropyDetector(
        entropy_threshold=entropy_threshold,
        min_token_length=min_token_length,
    )
    return detector.scan(
        content,
        repo=repo,
        file_path=file_path,
        commit_sha=commit_sha,
        author_email=author_email,
    )


def _is_false_positive_line(line: str) -> bool:
    lowered = line.lower()
    if "data:image/" in lowered and "base64," in lowered:
        return True

    if len(line) > 2_000 and line.count(";") > 20:
        return True

    return False

