import subprocess
import sys

def test_invalid_path_returns_exit_code_2():
    result = subprocess.run(
        [sys.executable, "cli.py", "scan", "doesnotexist.py"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_file_with_secrets_returns_exit_code_1():
    result = subprocess.run(
        [sys.executable, "cli.py", "scan", "test_secret.py"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 1
    assert "AWS Access Key" in result.stdout

def test_directory_scan_returns_exit_code_1(tmp_path):
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()

    secret_file = nested_dir / "config.py"
    secret_file.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "cli.py", "scan", str(tmp_path)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 1
    assert "AWS Access Key" in result.stdout

def test_clean_scan_returns_exit_code_0(tmp_path):
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("print('hello world')\n", encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "cli.py", "scan", str(clean_file)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert "Secret scan passed" in result.stdout


def test_no_subcommand_shows_usage_and_exits_nonzero():
    result = subprocess.run(
        [sys.executable, "cli.py"],
        capture_output=True,
        text=True
    )

    assert result.returncode == 2
    assert "usage" in result.stdout.lower()