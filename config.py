import json
import os

DEFAULT_CONFIG = {
    "min_severity": "LOW",
    "allowlist": [],
    "excluded_paths": []
}

def load_config(path="config.json"):
    if not os.path.exists(path):
        return DEFAULT_CONFIG

    with open(path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return DEFAULT_CONFIG

    # fill in any missing keys with defaults, in case the file is incomplete
    config = DEFAULT_CONFIG.copy()
    config.update(data)
    return config

def filter_results(results, config):
    filtered = []

    for r in results:
        if r["type"] in config["allowlist"]:
            continue

        if any(excluded in r["file"] for excluded in config["excluded_paths"]):
            continue

        filtered.append(r)

    return filtered