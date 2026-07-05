"""Local filesystem scan orchestration.

Unlike RepositoryScanner, this never talks to the GitHub API: it walks a
local directory or file directly, which is what makes it usable from a
pre-commit hook or as a standalone audit of a working tree.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from pathlib import Path

from secret_scanner.detectors.entropy_detector import EntropyDetector
from secret_scanner.detectors.regex_detector import RegexDetector
from secret_scanner.models import Finding
from secret_scanner.scanner import (
    DEFAULT_EXCLUDE_PATTERNS,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    Detector,
    path_matches_any_pattern,
)

ALWAYS_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "build",
        "dist",
    }
)
ALWAYS_EXCLUDED_DIR_SUFFIXES = (".egg-info",)


class LocalScanError(RuntimeError):
    """Raised when a local path cannot be scanned."""


class LocalScanner:
    def __init__(
        self,
        *,
        regex_detector: Detector | None = None,
        entropy_detector: Detector | None = None,
        exclude_patterns: Iterable[str] = DEFAULT_EXCLUDE_PATTERNS,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    ) -> None:
        if max_file_size_bytes < 0:
            raise ValueError("max_file_size_bytes must be >= 0")

        self._regex_detector = regex_detector or RegexDetector()
        self._entropy_detector = entropy_detector or EntropyDetector()
        self._exclude_patterns = tuple(exclude_patterns)
        self._max_file_size_bytes = max_file_size_bytes

    def scan_path(
        self,
        root: str | Path,
        *,
        exclude_patterns: Iterable[str] = (),
    ) -> list[Finding]:
        root_path = Path(root)
        if not root_path.exists():
            raise LocalScanError(f"path does not exist: {root_path}")

        active_excludes = self._exclude_patterns + tuple(exclude_patterns)
        repo_label = str(root_path)

        findings: list[Finding] = []
        for file_path, relative_path in self._iter_files(root_path):
            if path_matches_any_pattern(relative_path, active_excludes):
                continue

            if not self._within_size_limit(file_path):
                continue

            content = _read_text(file_path)
            if content is None:
                continue

            for detector in (self._regex_detector, self._entropy_detector):
                findings.extend(
                    detector.scan(
                        content,
                        repo=repo_label,
                        file_path=relative_path,
                    )
                )

        return findings

    def _within_size_limit(self, file_path: Path) -> bool:
        try:
            return file_path.stat().st_size <= self._max_file_size_bytes
        except OSError:
            return False

    def _iter_files(self, root_path: Path) -> Iterable[tuple[Path, str]]:
        if root_path.is_file():
            yield root_path, root_path.name
            return

        # Prune excluded directories in place so os.walk never descends into
        # them: on a monorepo this avoids stat-ing every file under, say, a
        # 200k-file node_modules just to discard it afterwards.
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = sorted(
                name for name in dirnames if not _is_always_excluded_dir(name)
            )
            for filename in sorted(filenames):
                file_path = Path(dirpath) / filename
                if not file_path.is_file():
                    continue

                yield file_path, file_path.relative_to(root_path).as_posix()


def _is_always_excluded_dir(name: str) -> bool:
    return name in ALWAYS_EXCLUDED_DIRS or name.endswith(ALWAYS_EXCLUDED_DIR_SUFFIXES)


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None
