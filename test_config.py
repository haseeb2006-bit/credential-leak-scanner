import json
import subprocess
import sys
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
    test_file = tmp_path / "secret.py"
    test_file.write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')

    results = scan_path(str(test_file))
    assert len(results) == 1

    results = scan_path(str(test_file), allowlist=["AKIAABCDEFGHIJKLMNOP"])
    assert len(results) == 0


def test_excluded_dirs_is_passed_to_scan_path(tmp_path):
    excluded_folder = tmp_path / "tests"
    excluded_folder.mkdir()
    test_file = excluded_folder / "secret.py"
    test_file.write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')

    results = scan_path(str(tmp_path))
    assert len(results) == 1

    results = scan_path(str(tmp_path), excluded_dirs=["tests"])
    assert len(results) == 0


def test_invalid_allowlist_type_falls_back_to_default(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"allowlist": "not-a-list"}))

    result = load_config(str(config_file))
    assert result["allowlist"] == []


def test_unknown_config_key_is_ignored(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"totally_made_up_key": "value"}))

    result = load_config(str(config_file))
    assert "totally_made_up_key" not in result


def test_cli_allowlist_from_config_skips_secret(tmp_path):
    secret_file = tmp_path / "secret.py"
    secret_file.write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')

    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"allowlist": ["AKIAABCDEFGHIJKLMNOP"]}))

    result = subprocess.run(
        [sys.executable, "cli.py", "scan", str(secret_file), "--config", str(config_file)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert "Secret scan passed" in result.stdout


def test_cli_excluded_dirs_from_config_skips_folder(tmp_path):
    excluded_folder = tmp_path / "tests"
    excluded_folder.mkdir()
    secret_file = excluded_folder / "secret.py"
    secret_file.write_text('aws_key = "AKIAABCDEFGHIJKLMNOP"')

    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"excluded_dirs": ["tests"]}))

    result = subprocess.run(
        [sys.executable, "cli.py", "scan", str(tmp_path), "--config", str(config_file)],
        capture_output=True,
        text=True
    )

    assert result.returncode == 0
    assert "Secret scan passed" in result.stdout


def test_non_dict_json_root_falls_back_to_defaults(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(["not", "a", "dict"]))

    result = load_config(str(config_file))
    assert result["allowlist"] == []
    assert result["excluded_dirs"] == []


def test_allowlist_with_non_string_items_falls_back_to_default(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"allowlist": [123, None, {"x": 1}]}))

    result = load_config(str(config_file))
    assert result["allowlist"] == []


def test_excluded_dirs_with_nested_list_falls_back_to_default(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"excluded_dirs": [["tests"]]}))

    result = load_config(str(config_file))
    assert result["excluded_dirs"] == []

def test_config_path_is_directory_falls_back_to_defaults(tmp_path):
    result = load_config(str(tmp_path))
    assert result["allowlist"] == []
    assert result["excluded_dirs"] == []