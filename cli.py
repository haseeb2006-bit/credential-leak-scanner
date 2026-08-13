import argparse
import os

def fake_scan_path(path):
    # TEMPORARY — pretends to be Huma's real scanner until it's ready
    return [
        {
            "file": path,
            "line": 1,
            "type": "AWS Access Key",
            "severity": "HIGH"
        }
    ]

def display_results(results):
    if not results:
        print("Secret scan passed. No issues found.")
        return

    for r in results:
        print(f"[{r['severity']}] {r['type']} detected")
        print(f"File: {r['file']}")
        print(f"Line: {r['line']}\n")

def collect_files(path):
    if os.path.isfile(path):
        return [path]

    file_list = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d != "__pycache__"]

        for filename in files:
            full_path = os.path.join(root, filename)
            file_list.append(full_path)
    return file_list

def main():
    parser = argparse.ArgumentParser(prog="secret-scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path")

    args = parser.parse_args()

    if args.command == "scan":
        if not os.path.isfile(args.path) and not os.path.isdir(args.path):
            print(f"Error: path '{args.path}' does not exist.")
            return

        files_to_scan = collect_files(args.path)

        all_results = []
        for file_path in files_to_scan:
            # TODO: replace fake_scan_path with Huma's real scanner once it's ready:
            # from scanner import scan_path
            # results = scan_path(file_path)
            results = fake_scan_path(file_path)
            all_results.extend(results)

        display_results(all_results)
        print(f"{len(files_to_scan)} file(s) scanned, {len(all_results)} potential secret(s) detected.")

if __name__ == "__main__":
    main()