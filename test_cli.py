import subprocess
import sys

def test_invalid_path_returns_exit_code_2():
    result = subprocess.run(
        [sys.executable, "cli.py", "scan", "doesnotexist.py"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 2
    assert "does not exist" in result.stdout


def test_file_with_secrets_returns_exit_code_1():
    result = subprocess.run(
        [sys.executable, "cli.py", "scan", "test_secret.py"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 1
    assert "AWS Access Key" in result.stdout

def test_directory_scan_returns_exit_code_1():
    result = subprocess.run(
        [sys.executable, "cli.py", "scan", "."],
        capture_output=True,
        text=True
    )

    assert result.returncode == 1