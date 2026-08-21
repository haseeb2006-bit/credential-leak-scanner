import json
import os

DEFAULT_CONFIG = {
    "allowlist": [],
    "excluded_dirs": []
}

ALLOWED_KEYS = set(DEFAULT_CONFIG.keys())


def validate_config(config):
    validated = config.copy()

    # warn about any keys that aren't part of the known config schema
    unknown_keys = set(validated.keys()) - ALLOWED_KEYS
    for key in unknown_keys:
        print(f"Warning: unknown config key '{key}' will be ignored.")
        del validated[key]

    if not isinstance(validated.get("allowlist"), list):
        print("Warning: 'allowlist' must be a list. Ignoring invalid value.")
        validated["allowlist"] = DEFAULT_CONFIG["allowlist"]

    if not isinstance(validated.get("excluded_dirs"), list):
        print("Warning: 'excluded_dirs' must be a list. Ignoring invalid value.")
        validated["excluded_dirs"] = DEFAULT_CONFIG["excluded_dirs"]

    return validated


def load_config(path="config.json"):
    if not os.path.exists(path):
        return DEFAULT_CONFIG.copy()

    with open(path, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: '{path}' is not valid JSON. Using default configuration.")
            return DEFAULT_CONFIG.copy()

    # fill in any missing keys with defaults, in case the file is incomplete
    config = DEFAULT_CONFIG.copy()
    config.update(data)
    return validate_config(config)