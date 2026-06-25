from __future__ import annotations

from pathlib import Path

import pytest

from secret_scanner.local_scanner import LocalScanError, LocalScanner


def test_scan_path_detects_regex_and_entropy_findings(tmp_path: Path) -> None:
    access_key = "AKIA" + "0000000000000000"
    high_entropy_token = "qR8vN3pLx9/ZtY2mK5" + "sD7fG1hJ4aC6bE0wUiOoP"
    (tmp_path / "app.env").write_text(
        f"AWS_ACCESS_KEY_ID={access_key}\nAPP_SECRET={high_entropy_token}\n",
        encoding="utf-8",
    )
    scanner = LocalScanner()

    findings = scanner.scan_path(tmp_path)

    assert [finding.detection_method for finding in findings] == ["regex", "entropy"]
    assert {finding.file_path for finding in findings} == {"app.env"}
    assert {finding.repo for finding in findings} == {str(tmp_path)}
    assert all("*" in finding.matched_text for finding in findings)


def test_scan_path_uses_relative_posix_paths_for_nested_files(tmp_path: Path) -> None:
    nested = tmp_path / "config" / "nested"
    nested.mkdir(parents=True)
    (nested / "settings.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIA1111111111111111\n", encoding="utf-8"
    )
    scanner = LocalScanner()

    findings = scanner.scan_path(tmp_path)

    assert [finding.file_path for finding in findings] == ["config/nested/settings.env"]


def test_scan_path_honors_exclude_patterns(tmp_path: Path) -> None:
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "app.min.js").write_text(
        "token = AKIA2222222222222222\n", encoding="utf-8"
    )
    (tmp_path / "src.py").write_text("token = AKIA3333333333333333\n", encoding="utf-8")
    scanner = LocalScanner()

    findings = scanner.scan_path(tmp_path, exclude_patterns=("*.min.js",))

    assert [finding.file_path for finding in findings] == ["src.py"]


@pytest.mark.parametrize(
    "excluded_dir",
    ["git", "node_modules", "venv", "__pycache__"],
)
def test_scan_path_always_skips_known_noise_directories(
    tmp_path: Path,
    excluded_dir: str,
) -> None:
    dir_name = f".{excluded_dir}" if excluded_dir == "git" else excluded_dir
    noisy_dir = tmp_path / dir_name
    noisy_dir.mkdir()
    (noisy_dir / "secret.env").write_text(
        "AWS_ACCESS_KEY_ID=AKIA4444444444444444\n", encoding="utf-8"
    )

    scanner = LocalScanner()

    findings = scanner.scan_path(tmp_path)

    assert findings == []


def test_scan_path_skips_files_over_the_size_limit(tmp_path: Path) -> None:
    big_file = tmp_path / "big.env"
    big_file.write_text("AWS_ACCESS_KEY_ID=AKIA5555555555555555\n", encoding="utf-8")
    scanner = LocalScanner(max_file_size_bytes=4)

    findings = scanner.scan_path(tmp_path)

    assert findings == []


def test_scan_path_skips_binary_files(tmp_path: Path) -> None:
    (tmp_path / "binary.dat").write_bytes(b"\xff\xfe\x00\x01AKIA6666666666666666")
    scanner = LocalScanner()

    findings = scanner.scan_path(tmp_path)

    assert findings == []


def test_scan_path_accepts_a_single_file(tmp_path: Path) -> None:
    file_path = tmp_path / "app.env"
    file_path.write_text("AWS_ACCESS_KEY_ID=AKIA7777777777777777\n", encoding="utf-8")
    scanner = LocalScanner()

    findings = scanner.scan_path(file_path)

    assert [finding.file_path for finding in findings] == ["app.env"]


def test_scan_path_rejects_missing_path(tmp_path: Path) -> None:
    scanner = LocalScanner()

    with pytest.raises(LocalScanError, match="does not exist"):
        scanner.scan_path(tmp_path / "missing")


def test_local_scanner_rejects_negative_max_file_size() -> None:
    with pytest.raises(ValueError, match="max_file_size_bytes"):
        LocalScanner(max_file_size_bytes=-1)
