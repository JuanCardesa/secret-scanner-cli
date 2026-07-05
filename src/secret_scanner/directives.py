"""Inline suppression directives.

A developer can silence a specific line without maintaining a baseline entry
by adding an inline comment, matching the ergonomics of `gitleaks:allow` and
detect-secrets' `pragma: allowlist secret`.
"""

from __future__ import annotations

import re

# Matched case-insensitively anywhere on the line, so it works regardless of
# the host language's comment syntax (`#`, `//`, `/* */`, ...).
IGNORE_DIRECTIVE_RE = re.compile(
    r"secret-scanner:\s*(?:ignore|allow)|pragma:\s*allowlist\s+secret",
    re.IGNORECASE,
)


def line_has_ignore_directive(line: str) -> bool:
    """Return True if the line opts out of secret detection."""
    return IGNORE_DIRECTIVE_RE.search(line) is not None
