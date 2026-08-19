import os
import json
from config import load_config, filter_results


def test_load_valid_config(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({"min_severity": "HIGH"}))

    result = load_config(str(config_file))
    assert result["min_severity"] == "HIGH"


def test_missing_config_falls_back_to_defaults(tmp_path):
    missing_path = tmp_path / "does_not_exist.json"

    result = load_config(str(missing_path))
    assert result["min_severity"] == "LOW"


def test_allowlist_filters_out_matching_type():
    results = [
        {"file": "a.py", "line": 1, "type": "AWS Access Key", "severity": "HIGH"},
        {"file": "b.py", "line": 2, "type": "Test Key", "severity": "LOW"},
    ]
    config = {"allowlist": ["Test Key"], "excluded_paths": []}

    filtered = filter_results(results, config)
    assert len(filtered) == 1
    assert filtered[0]["type"] == "AWS Access Key"


def test_excluded_paths_filters_out_matching_file():
    results = [
        {"file": "src/config.py", "line": 1, "type": "AWS Access Key", "severity": "HIGH"},
        {"file": "tests/fake.py", "line": 2, "type": "AWS Access Key", "severity": "HIGH"},
    ]
    config = {"allowlist": [], "excluded_paths": ["tests/"]}

    filtered = filter_results(results, config)
    assert len(filtered) == 1
    assert filtered[0]["file"] == "src/config.py"