"""Regex-based secret detection."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from secret_scanner.models import Finding, SecretPattern, redact_secret

DEFAULT_PATTERNS_PATH = Path(__file__).resolve().parents[1] / "patterns.yaml"
VALID_CONFIDENCE = {"high", "medium", "low"}


class PatternLoadError(ValueError):
    """Raised when pattern configuration cannot be loaded."""


def load_patterns(
    patterns_path: str | Path = DEFAULT_PATTERNS_PATH,
) -> list[SecretPattern]:
    """Load regex patterns from an external YAML file.

    Phase 1 keeps this dependency-light by accepting JSON-compatible YAML.
    If PyYAML is installed later, standard YAML files are also supported.
    """
    path = Path(patterns_path)
    raw = path.read_text(encoding="utf-8")

    try:
        import yaml  # type: ignore[import-not-found,import-untyped]

        parsed = yaml.safe_load(raw)
    except ModuleNotFoundError:
        parsed = json.loads(raw)

    entries = parsed.get("patterns") if isinstance(parsed, dict) else parsed
    if not isinstance(entries, list):
        raise PatternLoadError("patterns.yaml must contain a list or a 'patterns' list")

    patterns: list[SecretPattern] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise PatternLoadError(f"pattern entry {index} must be a mapping")

        try:
            name = str(entry["name"])
            regex = str(entry["regex"])
            confidence = str(entry["confidence"]).lower()
            example = str(entry["example"])
        except KeyError as exc:
            raise PatternLoadError(
                f"pattern entry {index} missing field: {exc.args[0]}"
            ) from exc

        if confidence not in VALID_CONFIDENCE:
            raise PatternLoadError(
                f"pattern '{name}' has invalid confidence '{confidence}'"
            )

        try:
            re.compile(regex)
        except re.error as exc:
            raise PatternLoadError(
                f"pattern '{name}' has invalid regex: {exc}"
            ) from exc

        patterns.append(
            SecretPattern(
                name=name,
                regex=regex,
                confidence=confidence,  # type: ignore[arg-type]
                example=example,
            )
        )

    return patterns


class RegexDetector:
    def __init__(self, patterns: Sequence[SecretPattern] | None = None) -> None:
        self.patterns = list(patterns) if patterns is not None else load_patterns()
        self._compiled = [
            (pattern, re.compile(pattern.regex, re.MULTILINE | re.DOTALL))
            for pattern in self.patterns
        ]

    def scan(
        self,
        content: str,
        *,
        repo: str = "",
        file_path: str = "",
        commit_sha: str = "",
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()

        for pattern, compiled in self._compiled:
            for match in compiled.finditer(content):
                matched_value = _selected_match_value(match)
                if not matched_value:
                    continue

                line_number = content.count("\n", 0, match.start()) + 1
                fingerprint = (pattern.name, line_number, matched_value)
                if fingerprint in seen:
                    continue

                seen.add(fingerprint)
                findings.append(
                    Finding(
                        repo=repo,
                        file_path=file_path,
                        line_number=line_number,
                        matched_text=redact_secret(matched_value),
                        detection_method="regex",
                        pattern_name=pattern.name,
                        confidence=pattern.confidence,
                        commit_sha=commit_sha,
                    )
                )

        return findings


def scan_content(
    content: str,
    *,
    patterns: Iterable[SecretPattern] | None = None,
    repo: str = "",
    file_path: str = "",
    commit_sha: str = "",
) -> list[Finding]:
    detector = RegexDetector(list(patterns) if patterns is not None else None)
    return detector.scan(
        content,
        repo=repo,
        file_path=file_path,
        commit_sha=commit_sha,
    )


def _selected_match_value(match: re.Match[str]) -> str:
    if "secret" in match.re.groupindex:
        return match.group("secret")
    return match.group(0)
