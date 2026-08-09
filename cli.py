import argparse

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

def main():
    parser = argparse.ArgumentParser(prog="secret-scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path")

    args = parser.parse_args()

    if args.command == "scan":
        # TODO: replace fake_scan_path with Huma's real scanner once it's ready:
        # from scanner import scan_path
        # results = scan_path(args.path)
        results = fake_scan_path(args.path)
        display_results(results)

if __name__ == "__main__":
    main()