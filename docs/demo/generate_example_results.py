"""Generate redacted demo reports from synthetic local fixtures."""

from __future__ import annotations

# ruff: noqa: E402,I001

import random
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
SRC_DIR = ROOT_DIR / "src"
DEMO_DIR = Path(__file__).resolve().parent
GENERATED_DIR = DEMO_DIR / ".generated"
REPORTS_DIR = DEMO_DIR / "reports"
DEMO_REPO = "demo/local-fixture"
DEMO_COMMIT_SHA = "demo-local-commit"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from secret_scanner.detectors.entropy_detector import EntropyDetector  # noqa: E402
from secret_scanner.detectors.regex_detector import RegexDetector  # noqa: E402
from secret_scanner.models import Finding  # noqa: E402
from secret_scanner.reporter import render_html, render_json, render_terminal  # noqa: E402


def main() -> int:
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    for relative_path, content in _demo_files().items():
        target = GENERATED_DIR / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    findings = _scan_demo_fixture(GENERATED_DIR)
    _write_report("example-terminal.txt", render_terminal(findings, use_color=False))
    _write_report("example-report.json", render_json(findings))
    _write_report("example-report.html", render_html(findings))

    relative_reports_dir = REPORTS_DIR.relative_to(ROOT_DIR)
    print(f"Wrote {len(findings)} redacted demo findings to {relative_reports_dir}")
    return 0


def _demo_files() -> dict[str, str]:
    fake_aws_access_key = "AKIA" + ("0" * 16)
    fake_github_token = "ghp_" + ("A" * 36)
    fake_stripe_key = "sk_live_" + ("B" * 24)
    fake_high_entropy_token = _stable_high_entropy_token()

    return {
        "app.env": "\n".join(
            [
                (
                    "# Synthetic demo fixture. Values are generated for "
                    "scanner tests only."
                ),
                f"AWS_ACCESS_KEY_ID={fake_aws_access_key}",
                f"GITHUB_TOKEN={fake_github_token}",
                f"STRIPE_SECRET_KEY={fake_stripe_key}",
                f'INTERNAL_SESSION_SECRET = "{fake_high_entropy_token}"',
                "SAFE_PLACEHOLDER=not-a-secret",
                "",
            ]
        ),
        "README.txt": "\n".join(
            [
                "This generated fixture exists only to demonstrate report output.",
                "It is ignored by Git and contains no real credentials.",
                "",
            ]
        ),
    }


def _stable_high_entropy_token() -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+/="
    rng = random.Random(1337)
    return "".join(rng.choice(alphabet) for _ in range(48))


def _scan_demo_fixture(fixture_dir: Path) -> list[Finding]:
    regex_detector = RegexDetector()
    entropy_detector = EntropyDetector()
    findings: list[Finding] = []

    for path in sorted(fixture_dir.rglob("*")):
        if not path.is_file():
            continue

        relative_path = path.relative_to(fixture_dir).as_posix()
        content = path.read_text(encoding="utf-8")
        for detector in (regex_detector, entropy_detector):
            findings.extend(
                detector.scan(
                    content,
                    repo=DEMO_REPO,
                    file_path=relative_path,
                    commit_sha=DEMO_COMMIT_SHA,
                )
            )

    return findings


def _write_report(file_name: str, content: str) -> None:
    (REPORTS_DIR / file_name).write_text(content + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
