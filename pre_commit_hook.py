import sys
import os
import tempfile
from pathlib import Path
from staged_files import get_staged_files, get_staged_content
from scanner import scan_path, is_excluded_path, DEFAULT_EXCLUDED_DIRS
from config import load_config
from cli import display_results


def scan_staged_file(filename, allowlist, excluded_dirs):
    # Check exclusion against the ORIGINAL file path before flattening
    # it into a temp file — otherwise a staged file inside an excluded
    # directory (e.g. "generated/config.py") would lose that folder
    # structure once written to a flat temp file, and the exclusion
    # would silently stop applying.
    effective_excluded_dirs = DEFAULT_EXCLUDED_DIRS | set(excluded_dirs or [])
    if is_excluded_path(Path(filename), effective_excluded_dirs):
        return []

    content = get_staged_content(filename)
    suffix = Path(filename).suffix

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        delete=False,
        encoding="utf-8"
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        results = scan_path(
            tmp_path,
            allowlist=allowlist,
            excluded_dirs=excluded_dirs
        )

        for result in results:
            result["file"] = filename

        return results

    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def main():
    try:
        staged = get_staged_files()
    except RuntimeError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    if not staged:
        sys.exit(0)

    config = load_config()

    all_results = []

    try:
        for filename in staged:
            results = scan_staged_file(
                filename,
                allowlist=config["allowlist"],
                excluded_dirs=config["excluded_dirs"]
            )
            all_results.extend(results)
    except RuntimeError as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(2)

    if all_results:
        print("Git Secret Scanner")
        print("Scanning staged files...\n")
        display_results(all_results)
        print("\nCommit blocked: secrets detected in staged files.")
        sys.exit(1)

    print("Secret scan passed. No issues found.")
    sys.exit(0)


if __name__ == "__main__":
    main()