import argparse
import os
import sys
from scanner import scan_path


def display_results(results):
    if not results:
        print("Secret scan passed. No issues found.")
        return
    # visually display the findings
    for r in results:
        print(f"[{r['severity']}] {r['type']} detected")
        print(f"File: {r['file']}")
        print(f"Line: {r['line']}\n")


def main():
    # parse command line arguments
    parser = argparse.ArgumentParser(prog="secret-scanner")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("path", help = "The file or directory to scan for secrets")

    args = parser.parse_args()

    if args.command == "scan":
        if not os.path.exists(args.path):
            print(f"Error: path '{args.path}' does not exist.")
            sys.exit(2)

        results = scan_path(args.path)
        display_results(results)

        if results:
            sys.exit(1)
        else:
            sys.exit(0)

if __name__ == "__main__":
    main()