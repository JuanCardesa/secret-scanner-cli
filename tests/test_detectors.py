from __future__ import annotations

from pathlib import Path

import pytest

from secret_scanner.detectors.entropy_detector import EntropyDetector, shannon_entropy
from secret_scanner.detectors.regex_detector import RegexDetector, load_patterns

PATTERNS_PATH = (
    Path(__file__).resolve().parents[1] / "src" / "secret_scanner" / "patterns.yaml"
)
TEST_REPO = "trufflesecurity/test_keys"


def _synthetic_test_keys_new_key_fixture() -> str:
    access_key = "AKIA" + "0000000000000000"
    secret_key = "qR8vN3pLx9/ZtY2mK5" + "sD7fG1hJ4aC6bE0wUiOoP"
    return (
        "[default] aws_access_key_id = "
        f"{access_key} aws_secret_access_key = {secret_key} "
        "output = json region = us-east-2"
    )


def _synthetic_test_keys_private_key_fixture() -> str:
    return (
        "Basic auth: https://admin:admin@the-internet.herokuapp.com/basic_auth "
        "Private key: -----BEGIN OPENSSH PRIVATE KEY----- "
        "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0 "
        "-----END OPENSSH PRIVATE KEY-----"
    )


def test_regex_detector_loads_patterns_from_external_file() -> None:
    patterns = load_patterns(PATTERNS_PATH)

    assert {pattern.name for pattern in patterns} == {
        "AWS access key",
        "GitHub personal access token",
        "Stripe live API key",
        "PEM private key",
        "Generic JWT",
        "SendGrid API key",
    }


def test_regex_detector_detects_aws_access_key_from_test_keys_fixture() -> None:
    detector = RegexDetector(load_patterns(PATTERNS_PATH))

    findings = detector.scan(
        _synthetic_test_keys_new_key_fixture(),
        repo=TEST_REPO,
        file_path="new_key",
        commit_sha="fbc14303ffbf8fb1c2c1914e8dda7d0121633aca",
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.repo == TEST_REPO
    assert finding.file_path == "new_key"
    assert finding.line_number == 1
    assert finding.detection_method == "regex"
    assert finding.pattern_name == "AWS access key"
    assert finding.confidence == "high"
    assert finding.matched_text.startswith("AKIA")
    assert "*" in finding.matched_text
    assert "0000000000000000" not in finding.matched_text


def test_regex_detector_detects_private_key_from_test_keys_fixture_style() -> None:
    detector = RegexDetector(load_patterns(PATTERNS_PATH))

    findings = detector.scan(
        _synthetic_test_keys_private_key_fixture(),
        repo=TEST_REPO,
        file_path="keys",
    )

    assert len(findings) == 1
    assert findings[0].pattern_name == "PEM private key"
    assert findings[0].matched_text.startswith("-----BEGIN")
    assert "*" in findings[0].matched_text
    assert "b3BlbnNzaC1rZXktdjE" not in findings[0].matched_text


@pytest.mark.parametrize(
    ("content", "expected_pattern"),
    [
        ("token = " + "ghp_" + ("A" * 36), "GitHub personal access token"),
        ("token = " + "gho_" + ("B" * 36), "GitHub personal access token"),
        ("token = sk_live_" + ("C" * 24), "Stripe live API key"),
        (
            "jwt = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "Generic JWT",
        ),
        (
            "sendgrid = SG." + ("D" * 22) + "." + ("E" * 43),
            "SendGrid API key",
        ),
    ],
)
def test_regex_detector_covers_required_pattern_families(
    content: str,
    expected_pattern: str,
) -> None:
    detector = RegexDetector(load_patterns(PATTERNS_PATH))

    findings = detector.scan(content, file_path="fixture.txt")

    assert [finding.pattern_name for finding in findings] == [expected_pattern]
    assert all("*" in finding.matched_text for finding in findings)


def test_entropy_detector_flags_high_entropy_test_keys_secret() -> None:
    detector = EntropyDetector()

    findings = detector.scan(
        _synthetic_test_keys_new_key_fixture(),
        repo=TEST_REPO,
        file_path="new_key",
    )

    assert any(finding.detection_method == "entropy" for finding in findings)
    high_entropy_finding = findings[0]
    assert high_entropy_finding.pattern_name == "High entropy token"
    assert high_entropy_finding.confidence == "medium"
    assert high_entropy_finding.line_number == 1
    assert "*" in high_entropy_finding.matched_text
    assert "sD7fG1hJ4aC6bE0wUiOoP" not in high_entropy_finding.matched_text


def test_entropy_detector_ignores_low_entropy_tokens() -> None:
    detector = EntropyDetector()

    findings = detector.scan("placeholder = " + ("a" * 40), file_path="config.txt")

    assert findings == []
    assert shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == 0.0


@pytest.mark.parametrize(
    ("file_path", "content"),
    [
        ("package-lock.json", '"integrity": "sha512-' + ("A1b2C3d4E5f6G7h8" * 4) + '"'),
        ("dist/app.min.js", "var token='" + ("A1b2C3d4E5f6G7h8" * 4) + "';"),
        ("image.txt", "src=data:image/png;base64," + ("A1b2C3d4E5f6G7h8" * 4)),
    ],
)
def test_entropy_detector_ignores_common_false_positive_sources(
    file_path: str,
    content: str,
) -> None:
    detector = EntropyDetector()

    findings = detector.scan(content, file_path=file_path)

    assert findings == []
