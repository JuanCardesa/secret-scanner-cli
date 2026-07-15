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
        "AWS secret access key",
        "GitHub personal access token",
        "GitLab personal access token",
        "Stripe live API key",
        "PEM private key",
        "Generic JWT",
        "Anthropic API key",
        "OpenAI API key",
        "Hugging Face token",
        "SendGrid API key",
        "Google API key",
        "Slack token",
        "Slack webhook URL",
        "npm access token",
        "PyPI upload token",
        "DigitalOcean token",
        "Twilio API key",
        "Mailgun API key",
        "Azure storage account key",
        "Database connection string with credentials",
        "Discord bot token",
        "Telegram bot token",
        "Square access token",
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
        (
            "google = AIza" + ("F" * 35),
            "Google API key",
        ),
        (
            "slack = xoxb-" + ("g" * 20),
            "Slack token",
        ),
        (
            "webhook = https://hooks.slack.com/services/T"
            + ("0" * 9)
            + "/B"
            + ("1" * 9)
            + "/"
            + ("H" * 24),
            "Slack webhook URL",
        ),
        (
            "npm_token = npm_" + ("I" * 36),
            "npm access token",
        ),
        (
            "pypi_token = pypi-AgEIcHlwaS5vcmc" + ("J" * 60),
            "PyPI upload token",
        ),
        (
            "twilio = SK" + ("a" * 32),
            "Twilio API key",
        ),
        (
            "mailgun = key-" + ("K" * 32),
            "Mailgun API key",
        ),
        (
            "AccountKey=" + ("L" * 86) + "==",
            "Azure storage account key",
        ),
        (
            "DATABASE_URL=postgres://user:password@localhost:5432/app",
            "Database connection string with credentials",
        ),
        (
            "discord = M" + ("N" * 23) + "." + ("O" * 6) + "." + ("P" * 27),
            "Discord bot token",
        ),
        (
            "telegram = 123456789:" + ("Q" * 35),
            "Telegram bot token",
        ),
        (
            "square = sq0atp-" + ("R" * 22),
            "Square access token",
        ),
        (
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AWS secret access key",
        ),
        (
            "gitlab = glpat-" + ("S" * 20),
            "GitLab personal access token",
        ),
        (
            "anthropic = sk-ant-api03-" + ("t" * 90) + "AA",
            "Anthropic API key",
        ),
        (
            "openai = sk-" + ("U" * 24) + "T3BlbkFJ" + ("V" * 24),
            "OpenAI API key",
        ),
        (
            "hf = hf_" + ("w" * 36),
            "Hugging Face token",
        ),
        (
            "digitalocean = dop_v1_" + ("a" * 64),
            "DigitalOcean token",
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


def test_regex_detector_named_group_reports_only_the_secret() -> None:
    detector = RegexDetector(load_patterns(PATTERNS_PATH))

    findings = detector.scan(
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        file_path="app.env",
    )

    assert len(findings) == 1
    # The redacted value covers the credential, not the surrounding context.
    assert "aws_secret_access_key" not in findings[0].matched_text
    assert findings[0].matched_text.startswith("wJal")


def test_regex_detector_honors_inline_ignore_directive() -> None:
    detector = RegexDetector(load_patterns(PATTERNS_PATH))

    findings = detector.scan(
        "aws_key = AKIA0000000000000000  # secret-scanner:ignore",
        file_path="app.env",
    )

    assert findings == []


def test_entropy_detector_flags_hex_secret_below_base64_threshold() -> None:
    # A 64-char hex secret peaks at 4.0 bits/char, so the default 4.7 base64
    # floor can never catch it; the hex-aware floor must.
    hex_secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

    findings = EntropyDetector().scan(hex_secret, file_path="config.txt")

    assert len(findings) == 1
    assert findings[0].detection_method == "entropy"
    assert findings[0].entropy_score <= 4.0


def test_entropy_detector_classifies_hex_value_behind_an_assignment() -> None:
    # `NAME=<hex>` matches as one token; the leading identifier must not push
    # the value out of the hex threshold class.
    hex_secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

    findings = EntropyDetector().scan(
        f"SESSION_HMAC={hex_secret}", file_path="config.txt"
    )

    assert len(findings) == 1
    assert findings[0].detection_method == "entropy"


def test_entropy_detector_ignores_identifier_with_short_value() -> None:
    # `max_file_size_bytes=4`: the RHS is a single hex digit, so the whole
    # descriptive token must not be scored as a high-entropy hex secret.
    findings = EntropyDetector().scan("max_file_size_bytes=4", file_path="scanner.py")

    assert findings == []


def test_entropy_detector_honors_inline_ignore_directive() -> None:
    detector = EntropyDetector()
    secret = "qR8vN3pLx9ZtY2mK5sD7fG1hJ4aC6bE0wUiOoP"

    findings = detector.scan(
        f"token = {secret}  # secret-scanner:allow",
        file_path="config.txt",
    )

    assert findings == []


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


# A genuinely random base64-class secret used across the exclusion tests below:
# on its own (unremarkable path) it clears the default entropy floor and IS
# flagged, so each test proves the *exclusion* is what suppresses it.
_HIGH_ENTROPY_SECRET = "qR8vN3pLx9ZtY2mK5sD7fG1hJ4aC6bE0wUiOoP"


def test_entropy_secret_control_is_flagged_on_an_ordinary_path() -> None:
    findings = EntropyDetector().scan(
        f"token = {_HIGH_ENTROPY_SECRET}", file_path="src/app/config.py"
    )

    assert [f.detection_method for f in findings] == ["entropy"]


def test_entropy_detector_allowlists_dotted_namespace_paths() -> None:
    # A Java package/class reference clears the entropy floor only because '.'
    # is a token character; it is source code, not a secret.
    java_ref = "es.us.dp1.lx_xy_24_25.your_game_name.configuration.jwt.JwtUtils"

    findings = EntropyDetector().scan(f"import {java_ref};", file_path="Security.java")

    assert findings == []


def test_entropy_detector_still_flags_dotted_token_with_a_long_segment() -> None:
    # The namespace allowlist must not swallow real dotted secrets: a segment
    # longer than an identifier (here a random base64 run) keeps it in scope.
    dotted_secret = f"prefix.value.{_HIGH_ENTROPY_SECRET}"

    findings = EntropyDetector().scan(f"token = {dotted_secret}", file_path="config.py")

    assert [f.detection_method for f in findings] == ["entropy"]


@pytest.mark.parametrize(
    "file_path",
    [
        "backend/vagrant_venv/lib/python3.12/site-packages/certifi/cacert.pem",
        "node_modules/some-dep/index.js",
        "vendor/bundle/gem.rb",
        ".venv/lib/site.py",
        "frontend/dist/bundle.js",
    ],
)
def test_entropy_detector_skips_vendored_and_build_paths(file_path: str) -> None:
    findings = EntropyDetector().scan(
        f"value = {_HIGH_ENTROPY_SECRET}", file_path=file_path
    )

    assert findings == []


@pytest.mark.parametrize(
    "file_path",
    [
        "tests/test_scanner.py",
        "src/__tests__/auth.spec.ts",
        "spec/models_spec.rb",
        "fixtures/sample_payload.txt",
        "app/testdata/dump.txt",
        "auth_test.go",
    ],
)
def test_entropy_detector_skips_test_and_fixture_paths(file_path: str) -> None:
    findings = EntropyDetector().scan(
        f"value = {_HIGH_ENTROPY_SECRET}", file_path=file_path
    )

    assert findings == []


@pytest.mark.parametrize(
    "file_path",
    ["certs/ca-bundle.pem", "data/export.csv", "server.crt"],
)
def test_entropy_detector_skips_data_and_certificate_files(file_path: str) -> None:
    findings = EntropyDetector().scan(
        f"value = {_HIGH_ENTROPY_SECRET}", file_path=file_path
    )

    assert findings == []


def test_entropy_threshold_revision_drops_mid_entropy_tokens() -> None:
    # A 25-symbol run scores ~4.64 bits/char: above the old 4.5 floor, below the
    # revised 4.7 default. The default must now ignore it; a caller that lowers
    # the floor back to 4.5 must still catch it.
    mid_entropy = "abcdefghijklmnopqrstuvwxy"

    assert EntropyDetector().scan(f"k = {mid_entropy}", file_path="config.txt") == []
    lowered = EntropyDetector(entropy_threshold=4.5).scan(
        f"k = {mid_entropy}", file_path="config.txt"
    )
    assert [f.detection_method for f in lowered] == ["entropy"]


def test_regex_detector_still_flags_secrets_in_excluded_entropy_paths() -> None:
    # The vendored/test/fixture exclusions are scoped to the entropy detector.
    # A signature match (AWS key) in a test file is high-precision and must
    # still be reported -- this guards against the exclusions leaking into the
    # regex detector.
    detector = RegexDetector(load_patterns(PATTERNS_PATH))

    for file_path in (
        "tests/test_local_scanner.py",
        "backend/site-packages/boto/creds.py",
        "fixtures/aws.env",
    ):
        findings = detector.scan(
            "aws_access_key_id = AKIA0000000000000000",  # secret-scanner:ignore
            file_path=file_path,
        )
        assert [f.pattern_name for f in findings] == ["AWS access key"], file_path
