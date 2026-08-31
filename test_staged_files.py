import subprocess
from pathlib import Path

from staged_files import get_staged_files, get_staged_content
from pre_commit_hook import scan_staged_file


def _init_repo(tmp_path):
    # Each test uses its own temporary Git repository so the tests
    # stay isolated from the actual project repository.
    subprocess.run(
        ["git", "init"],
        cwd=tmp_path,
        capture_output=True
    )

    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=tmp_path,
        capture_output=True
    )

    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=tmp_path,
        capture_output=True
    )


def test_staged_new_file_is_included(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "example.py"
    test_file.write_text("print('hi')")

    subprocess.run(
        ["git", "add", "example.py"],
        capture_output=True
    )

    staged = get_staged_files()

    assert "example.py" in staged


def test_unstaged_file_is_excluded(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "example.py"
    test_file.write_text("print('hi')")

    staged = get_staged_files()

    assert "example.py" not in staged


def test_deleted_staged_file_is_ignored(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "example.py"
    test_file.write_text("print('hi')")

    subprocess.run(
        ["git", "add", "example.py"],
        capture_output=True
    )

    subprocess.run(
        ["git", "commit", "-m", "initial"],
        capture_output=True
    )

    test_file.unlink()

    subprocess.run(
        ["git", "add", "example.py"],
        capture_output=True
    )

    staged = get_staged_files()

    assert "example.py" not in staged


def test_modified_staged_file_is_included(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "example.py"
    test_file.write_text("print('hi')")

    subprocess.run(
        ["git", "add", "example.py"],
        capture_output=True
    )

    subprocess.run(
        ["git", "commit", "-m", "initial"],
        capture_output=True
    )

    test_file.write_text("print('changed')")

    subprocess.run(
        ["git", "add", "example.py"],
        capture_output=True
    )

    staged = get_staged_files()

    assert "example.py" in staged


def test_staged_content_keeps_secret_after_working_tree_changes(
    tmp_path,
    monkeypatch
):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "config.py"

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "config.py"],
        capture_output=True
    )

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = ""',
        encoding="utf-8"
    )

    staged_content = get_staged_content("config.py")

    assert "AKIAIOSFODNN7EXAMPLE" in staged_content


def test_staged_content_ignores_unstaged_secret(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "config.py"

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = ""',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "config.py"],
        capture_output=True
    )

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    staged_content = get_staged_content("config.py")

    assert "AKIAIOSFODNN7EXAMPLE" not in staged_content


def test_scan_staged_file_detects_secret_from_staged_version(
    tmp_path,
    monkeypatch
):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "config.py"

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "config.py"],
        capture_output=True
    )

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = ""',
        encoding="utf-8"
    )

    results = scan_staged_file(
        "config.py",
        allowlist=set(),
        excluded_dirs=set()
    )

    assert len(results) == 1
    assert results[0]["type"] == "AWS Access Key"


def test_scan_staged_file_ignores_unstaged_secret(
    tmp_path,
    monkeypatch
):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "config.py"

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = ""',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "config.py"],
        capture_output=True
    )

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    results = scan_staged_file(
        "config.py",
        allowlist=set(),
        excluded_dirs=set()
    )

    assert results == []


def test_staged_files_raises_when_git_fails(monkeypatch):
    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="",
            stderr="Git error"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    try:
        get_staged_files()

        assert False, (
            "Expected get_staged_files() to raise RuntimeError"
        )

    except RuntimeError as error:
        assert "Git could not read staged files" in str(error)


def test_pre_commit_hook_blocks_staged_secret(
    tmp_path,
    monkeypatch
):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "config.py"

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "config.py"],
        capture_output=True
    )

    hook_path = Path(__file__).parent / "pre_commit_hook.py"

    result = subprocess.run(
        ["python", str(hook_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path
    )

    assert result.returncode == 1
    assert "Commit blocked" in result.stdout


def test_pre_commit_hook_allows_clean_staged_file(
    tmp_path,
    monkeypatch
):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "config.py"

    test_file.write_text(
        'AWS_ACCESS_KEY_ID = ""',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "config.py"],
        capture_output=True
    )

    hook_path = Path(__file__).parent / "pre_commit_hook.py"

    result = subprocess.run(
        ["python", str(hook_path)],
        capture_output=True,
        text=True,
        cwd=tmp_path
    )

    assert result.returncode == 0
    assert "Secret scan passed" in result.stdout


def test_get_staged_content_raises_when_git_fails(monkeypatch):
    # Simulate Git failing so a broken Git call is never mistaken
    # for "no content" / a clean scan.

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout="",
            stderr="Git error"
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    try:
        get_staged_content("somefile.py")

        assert False, (
            "Expected get_staged_content() to raise RuntimeError"
        )

    except RuntimeError as error:
        assert "Git could not read staged content" in str(error)

def test_scan_staged_file_respects_excluded_dirs(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    excluded_folder = tmp_path / "generated"
    excluded_folder.mkdir()
    test_file = excluded_folder / "config.py"
    test_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "generated/config.py"],
        capture_output=True
    )

    results = scan_staged_file(
        "generated/config.py",
        allowlist=set(),
        excluded_dirs=["generated"]
    )

    assert results == []

def test_scan_staged_file_not_affected_by_temp_path_exclusion(
    tmp_path,
    monkeypatch
):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "config.py"
    test_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    subprocess.run(
        ["git", "add", "config.py"],
        capture_output=True
    )

    # "tmp" is a common substring in OS temp file paths.
    # If excluded_dirs were wrongly re-applied to the temp file,
    # this secret would be missed.
    results = scan_staged_file(
        "config.py",
        allowlist=set(),
        excluded_dirs=["tmp"]
    )

    assert len(results) == 1
    assert results[0]["type"] == "AWS Access Key"