import subprocess
from staged_files import get_staged_files


def _init_repo(tmp_path):
    # Create a temporary Git repository and configure a user
    # so commits can be made during the tests.
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
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
    subprocess.run(["git", "add", "example.py"], capture_output=True)

    # A newly created file that has been staged should be returned.
    staged = get_staged_files()
    assert "example.py" in staged


def test_unstaged_file_is_excluded(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "example.py"
    test_file.write_text("print('hi')")

    # The file exists, but was never staged with git add,
    # so it should not be included in the staged files.
    staged = get_staged_files()
    assert "example.py" not in staged


def test_deleted_staged_file_is_ignored(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "example.py"
    test_file.write_text("print('hi')")
    subprocess.run(["git", "add", "example.py"], capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], capture_output=True)

    test_file.unlink()
    subprocess.run(["git", "add", "example.py"], capture_output=True)

    # A deleted file can still appear in Git's staged changes,
    # but there is no file left to scan, so it should be ignored.
    staged = get_staged_files()
    assert "example.py" not in staged


def test_modified_staged_file_is_included(tmp_path, monkeypatch):
    _init_repo(tmp_path)
    monkeypatch.chdir(tmp_path)

    test_file = tmp_path / "example.py"
    test_file.write_text("print('hi')")
    subprocess.run(["git", "add", "example.py"], capture_output=True)
    subprocess.run(["git", "commit", "-m", "initial"], capture_output=True)

    test_file.write_text("print('changed')")
    subprocess.run(["git", "add", "example.py"], capture_output=True)

    # A previously committed file that has been modified and staged
    # should still be included in the files returned for scanning.
    staged = get_staged_files()
    assert "example.py" in staged