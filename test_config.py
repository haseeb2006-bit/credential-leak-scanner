import json
from config import load_config
from scanner import scan_path


def test_load_valid_config(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"allowlist": ["ABC123"]}))

    result = load_config(str(config_file))
    assert result["allowlist"] == ["ABC123"]


def test_missing_config_falls_back_to_defaults():
    result = load_config("does_not_exist.json")
    assert result["allowlist"] == []
    assert result["excluded_dirs"] == []


def test_allowlist_is_passed_to_scan_path(tmp_path):
    # create a temp file containing a fake AWS key
    test_file = tmp_path / "secret.py"
    test_file.write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')

    # without allowlist, it should be detected
    results = scan_path(str(test_file))
    assert len(results) == 1

    # with the exact value allowlisted, it should be skipped
    results = scan_path(str(test_file), allowlist=["AKIAABCDEFGHIJKLMNOP"])
    assert len(results) == 0


def test_excluded_dirs_is_passed_to_scan_path(tmp_path):
    # create a subfolder named "tests" containing a fake secret
    excluded_folder = tmp_path / "tests"
    excluded_folder.mkdir()
    test_file = excluded_folder / "secret.py"
    test_file.write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')

    # without excluding it, the file should be found and scanned
    results = scan_path(str(tmp_path))
    assert len(results) == 1

    # with "tests" excluded, it should be skipped entirely
    results = scan_path(str(tmp_path), excluded_dirs=["tests"])
    assert len(results) == 0