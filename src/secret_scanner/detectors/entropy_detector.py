"""Shannon entropy-based secret detection."""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from secret_scanner.directives import line_has_ignore_directive
from secret_scanner.models import Finding, redact_secret, shannon_entropy

TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_./+=:-]{21,}(?![A-Za-z0-9])")
HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]+$")
# The token charset includes '=' and ':', so `HEX_KEY=deadbeef...` matches as a
# single token; strip a leading `name=` / `name:` so length, entropy, and the
# hex-vs-base64 threshold all judge the value, not the identifier glued to it.
ASSIGNMENT_PREFIX_RE = re.compile(r"^[A-Za-z0-9_.-]+[=:](?P<value>.+)$")
# A dotted namespace / import path -- a Java package reference like
# `es.us.dp1.app.configuration.jwt.JwtUtils`, a Python dotted module, etc. Such
# tokens only clear the entropy floor because '.' is in the token charset; they
# are source-code identifiers, never secrets. Every '.'-separated segment must
# be a short identifier: long segments (e.g. base64 JWT parts) are not, so real
# dotted secrets stay in scope. See _is_dotted_namespace.
NAMESPACE_SEGMENT_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
NAMESPACE_MIN_SEGMENTS = 3
NAMESPACE_MAX_SEGMENT_LENGTH = 30
# Base64/base62-class tokens draw from a ~64-symbol alphabet (max entropy 6
# bits/char). The floor sits at 4.7: real random secrets score 5.0-6.0, while
# structured, human-authored strings (dotted paths, prose, config identifiers)
# cluster below it -- raising the old 4.5 floor sheds that low-signal band
# without losing genuine high-entropy credentials. Hex tokens draw from only 16
# symbols (max entropy 4.0 bits/char), so the same floor would make every hex
# secret undetectable; they get a proportionally lower floor.
DEFAULT_ENTROPY_THRESHOLD = 4.7
DEFAULT_HEX_ENTROPY_THRESHOLD = 3.0
DEFAULT_MIN_TOKEN_LENGTH = 21
DEFAULT_EXCLUDED_PATHS = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "Cargo.lock",
    "composer.lock",
    "go.sum",
    "*.min.js",
    "*.map",
    # Vendored dependencies, virtualenvs and build output are not the author's
    # code; entropy-scanning a committed venv's CA bundle or node_modules floods
    # the report with third-party noise. (Signature/regex detectors still scan
    # these paths, so a real key vendored by mistake is not missed.)
    "*/node_modules/*",
    "node_modules/*",
    "*/site-packages/*",
    "site-packages/*",
    "*/vendor/*",
    "vendor/*",
    "*/dist/*",
    "dist/*",
    "*/build/*",
    "build/*",
    "*/.tox/*",
    "*/__pycache__/*",
    "*venv*/*",
    "*/.venv/*",
    ".venv/*",
    # Test and fixture trees: high-entropy strings here are sample/mock data, not
    # live credentials. Scoped to the entropy detector only -- a real signature
    # match (e.g. an AWS key) in a test file is still reported.
    "*/tests/*",
    "tests/*",
    "*/test/*",
    "test/*",
    "*/__tests__/*",
    "*/spec/*",
    "spec/*",
    "*/specs/*",
    "*/fixtures/*",
    "fixtures/*",
    "*/__fixtures__/*",
    "*/__mocks__/*",
    "*/mocks/*",
    "*/testdata/*",
    "testdata/*",
    "test_*.*",
    "*_test.*",
    "*.test.*",
    "*.spec.*",
)
IMAGE_EXTENSIONS = {".gif", ".jpg", ".jpeg", ".png", ".webp", ".ico", ".svg"}
# Bulk data / certificate files: PEM bundles are base64 certs (real PEM private
# keys are still caught by the regex "PEM private key" detector), and CSV/TSV
# data dumps produce entropy noise column by column.
DATA_CERT_EXTENSIONS = {".pem", ".crt", ".cer", ".csv", ".tsv"}
EXCLUDED_SUFFIXES = IMAGE_EXTENSIONS | DATA_CERT_EXTENSIONS


class EntropyDetector:
    def __init__(
        self,
        *,
        entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
        hex_entropy_threshold: float = DEFAULT_HEX_ENTROPY_THRESHOLD,
        min_token_length: int = DEFAULT_MIN_TOKEN_LENGTH,
        excluded_paths: Iterable[str] = DEFAULT_EXCLUDED_PATHS,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.hex_entropy_threshold = hex_entropy_threshold
        self.min_token_length = min_token_length
        self.excluded_paths = tuple(excluded_paths)

    def scan(
        self,
        content: str,
        *,
        repo: str = "",
        file_path: str = "",
        commit_sha: str = "",
    ) -> list[Finding]:
        if self._is_excluded_file(file_path):
            return []

        findings: list[Finding] = []
        seen: set[tuple[int, str]] = set()

        for line_number, line in enumerate(content.splitlines(), start=1):
            if _is_false_positive_line(line) or line_has_ignore_directive(line):
                continue

            for match in TOKEN_RE.finditer(line):
                raw = match.group(0).strip(".,;\"'`)]}>")
                candidate = self._secret_candidate(raw)
                if len(candidate) < self.min_token_length:
                    continue

                if _is_dotted_namespace(candidate):
                    continue

                # Score entropy on the same string used to pick the threshold,
                # so a low-entropy identifier glued to a short value (e.g.
                # `max_file_size_bytes=4`) can't be scored as one thing and
                # classified as another.
                candidate_entropy = shannon_entropy(candidate)
                if candidate_entropy <= self._threshold_for(candidate):
                    continue

                fingerprint = (line_number, candidate)
                if fingerprint in seen:
                    continue

                seen.add(fingerprint)
                findings.append(
                    Finding(
                        repo=repo,
                        file_path=file_path,
                        line_number=line_number,
                        matched_text=redact_secret(candidate),
                        detection_method="entropy",
                        pattern_name="High entropy token",
                        confidence="medium",
                        commit_sha=commit_sha,
                        entropy_score=candidate_entropy,
                    )
                )

        return findings

    def _secret_candidate(self, token: str) -> str:
        """Narrow `name=value` / `name:value` to the value when it stands alone.

        Only strips the identifier when the value is itself long enough to be a
        token; otherwise the whole match is kept, which avoids splitting a
        base64 value at its own `=` padding.
        """
        prefix_match = ASSIGNMENT_PREFIX_RE.match(token)
        if prefix_match is not None:
            value = prefix_match.group("value")
            if len(value) >= self.min_token_length:
                return value
        return token

    def _threshold_for(self, token: str) -> float:
        if HEX_TOKEN_RE.match(token):
            return self.hex_entropy_threshold
        return self.entropy_threshold

    def _is_excluded_file(self, file_path: str) -> bool:
        normalized = file_path.replace("\\", "/")
        name = PurePosixPath(normalized).name
        suffix = PurePosixPath(normalized).suffix.lower()

        if suffix in EXCLUDED_SUFFIXES:
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
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    hex_entropy_threshold: float = DEFAULT_HEX_ENTROPY_THRESHOLD,
    min_token_length: int = DEFAULT_MIN_TOKEN_LENGTH,
) -> list[Finding]:
    detector = EntropyDetector(
        entropy_threshold=entropy_threshold,
        hex_entropy_threshold=hex_entropy_threshold,
        min_token_length=min_token_length,
    )
    return detector.scan(
        content,
        repo=repo,
        file_path=file_path,
        commit_sha=commit_sha,
    )


def _is_dotted_namespace(token: str) -> bool:
    """Return True for dotted import/namespace paths (not secrets).

    A token qualifies when it is at least ``NAMESPACE_MIN_SEGMENTS`` dot-
    separated identifier segments and no single segment is longer than
    ``NAMESPACE_MAX_SEGMENT_LENGTH``. The length cap is what keeps real dotted
    secrets in scope: a JWT's base64 segments run far longer than any Java or
    Python identifier, so they never match.
    """
    segments = token.split(".")
    if len(segments) < NAMESPACE_MIN_SEGMENTS:
        return False
    for segment in segments:
        if not NAMESPACE_SEGMENT_RE.fullmatch(segment):
            return False
        if len(segment) > NAMESPACE_MAX_SEGMENT_LENGTH:
            return False
    return True


def _is_false_positive_line(line: str) -> bool:
    lowered = line.lower()
    if "data:image/" in lowered and "base64," in lowered:
        return True

    if len(line) > 2_000 and line.count(";") > 20:
        return True

    return False
