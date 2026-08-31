import sys
import os
import tempfile
from pathlib import Path
from staged_files import get_staged_files, get_staged_content
from scanner import scan_path, is_excluded_path, DEFAULT_EXCLUDED_DIRS
from config import load_config
from cli import display_results


def scan_staged_file(filename, allowlist, excluded_dirs):
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
        # excluded_dirs is intentionally NOT passed here — we already
        # checked exclusion against the real staged filename above.
        # Re-checking against the temp file's path could wrongly match
        # (e.g. a user excluding "tmp" would accidentally skip every
        # temp file, since OS temp paths often contain "tmp").
        results = scan_path(
            tmp_path,
            allowlist=allowlist
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