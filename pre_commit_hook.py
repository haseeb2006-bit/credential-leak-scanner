import sys
from staged_files import get_staged_files
from scanner import scan_path
from config import load_config
from cli import display_results


def main():
    staged = get_staged_files()

    # Nothing is staged, so there is nothing to scan.
    if not staged:
        sys.exit(0)

    config = load_config()

    all_results = []
    for file in staged:
        results = scan_path(
            file,
            allowlist=config["allowlist"],
            excluded_dirs=config["excluded_dirs"]
        )
        all_results.extend(results)

    # Block the commit if any secrets were found.
    if all_results:
        print("Git Secret Scanner")
        print("Scanning staged files...\n")
        display_results(all_results)
        print("Commit blocked: secrets detected in staged files.")
        sys.exit(1)

    print("Secret scan passed. No issues found.")
    sys.exit(0)


if __name__ == "__main__":
    main()