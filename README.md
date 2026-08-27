# Git Secret & Credential Leak Scanner

A Python-based DevSecOps tool that detects accidentally exposed credentials — API keys, tokens, passwords, and private keys — in source code before they reach version control. Built as a learning project by two developers to understand how tools like Gitleaks and TruffleHog work under the hood, and to practice secure software development as a team.

## Why This Project?

Leaked credentials are one of the most common and preventable causes of real-world security breaches. A single hardcoded API key pushed to a public repository can be found and exploited within minutes.

This project explores how automated secret detection works — combining pattern matching with statistical analysis — and how that detection can be integrated directly into a developer's workflow, rather than discovered after the fact.

## How It Works

The scanner inspects source files using two complementary techniques:

* **Pattern-based detection** — regular expressions that match the structure of known credential formats, such as AWS access keys or GitHub tokens.
* **Entropy-based detection** — Shannon entropy analysis to flag strings that look statistically random, helping catch secrets that do not match any known pattern.

Together, these methods allow the scanner to catch both well-known credential formats and unfamiliar, randomly generated secrets.

## Architecture

```text
Developer
    ↓
   CLI
    ↓
 Scanner
    ↓
Regex Detection + Entropy Detection
    ↓
 Findings
    ↓
CLI / Git Hook / GitHub Action
```

The CLI, Git pre-commit hook, and GitHub Action all call the same underlying scanner rather than duplicating detection logic.

The scanner exposes a simple interface:

```python
scan_path(path, allowlist=None, excluded_dirs=None)
```

which returns findings in a consistent format:

```python
[
    {
        "file": "config.py",
        "line": 14,
        "type": "AWS Access Key",
        "severity": "HIGH"
    }
]
```

This shared format allows the CLI, Git hook, and CI integration to consume scan results consistently.

## Detection Methods

### Regex-Based Detection

Regex-based detection targets known credential formats, including:

* AWS access keys
* GitHub personal access tokens and fine-grained tokens
* RSA and OpenSSH private keys
* JWT-style tokens
* Generic API tokens
* Password assignments

### Entropy-Based Detection

Entropy-based detection calculates the randomness of a string using Shannon entropy.

High-entropy strings, such as:

```text
xK9mP2qL8VzR7BwN5JsQ
```

can be statistically unlikely to be normal words or identifiers and may therefore be flagged as potential secrets, particularly when paired with suspicious variable names such as:

```text
api_key
token
secret
password
```

### False-Positive Reduction

The scanner reduces false positives using several safeguards:

* Minimum string length
* Allowlists for approved values
* Exclusion of common placeholder or example credentials
* Entropy threshold filtering
* Skipping binary files
* Skipping files larger than 5 MB

## Installation

Clone the repository:

```bash
git clone https://github.com/haseeb2006-bit/credential-leak-scanner.git
cd credential-leak-scanner
```

Requires Python 3.10 or later.

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Scan a single file or an entire directory:

```bash
python cli.py scan example.py
python cli.py scan .
```

Example output:

```text
[HIGH] AWS Access Key detected
File: example.py
Line: 5

Secret scan passed. No issues found.
```

Use a custom configuration file:

```bash
python cli.py scan . --config myconfig.json
```

If `--config` is not provided, the scanner looks for `config.json` in the current directory by default.

If the given path doesn't exist, the CLI prints an error and exits with a non-zero status rather than reporting a false "clean" result.

## Exit Codes

The CLI returns the following exit codes, used by both the pre-commit hook and GitHub Actions to determine pass/fail:

```text
0 = scan completed successfully, no secrets found
1 = secrets detected
2 = invalid path, CLI usage error, or Git/staged-scan failure
```

## Configuration

Configuration is provided via a JSON file (default: `config.json`):

```json
{
    "allowlist": ["YOUR_APPROVED_KEY_VALUE_HERE"],
    "excluded_dirs": ["fixtures", "generated"]
}
```

* **`allowlist`** — exact secret values that should be ignored, e.g. known-safe example credentials used in documentation.
* **`excluded_dirs`** — additional directory or file names to skip during scanning, on top of built-in default directories (`.git`, `.venv`, `venv`, `node_modules`, `dist`, `build`, `vendor`). This project's own `config.json` uses it to exclude test fixture files that intentionally contain fake secrets.

If the config file is missing, the scanner falls back to safe defaults silently. If the file is present but malformed or contains invalid values, the scanner logs a warning and falls back to defaults rather than failing.

## Git Pre-Commit Integration

The project includes a pre-commit hook that scans only the files currently staged for commit — not the entire repository, and not the working-tree copy. It reads the exact content stored in Git's staging area (via `git show`), so a secret that's staged but later edited out of the working file is still caught, and an unstaged secret in the working file does not incorrectly block a clean commit.

To install it on your machine:

```bash
python install_hook.py
```

This writes the hook into `.git/hooks/pre-commit`, which Git automatically runs before every commit. Since `.git/hooks/` isn't tracked by Git, each contributor needs to run this once after cloning the repository. If a pre-commit hook already exists, `install_hook.py` will not overwrite it.

Behavior:

* Newly added and modified staged files are scanned using their exact staged content.
* Deleted staged files are ignored.
* If a secret is found, the commit is blocked and the findings are printed.
* If the scan is clean, the commit proceeds normally.
* If Git itself fails while reading staged files or content, the hook reports an error and blocks the commit rather than assuming a clean scan.

## GitHub Actions

A GitHub Actions workflow (`.github/workflows/secret-scan.yml`) automatically runs on every Pull Request and on every push to `main`. It first runs the full test suite, then scans the entire repository (`python cli.py scan .`) using the same CLI as local development — no separate detection logic — and relies on the CLI's exit code to determine whether the check passes or fails.

## Testing

The project includes automated tests (53 tests total, run via `pytest`) covering:

* Detection logic, directory scanning, allowlisting, exclusions, false-positive reduction, and file-handling edge cases (`test_scanner.py`)
* CLI behavior, including path validation and exit codes (`test_cli.py`)
* Configuration loading and validation, including CLI-level integration tests (`test_config.py`)
* Staged-file discovery, staged-content accuracy, and pre-commit hook behavior, including real Git integration tests (`test_staged_files.py`)

Run the full test suite with:

```bash
pytest
```

Test fixtures never contain real credentials. Only fake or officially documented example values are used.

## Security Considerations

* This is an educational/portfolio project and is not intended to replace mature, production-grade tools such as Gitleaks or TruffleHog.
* Test credentials are always fake or officially documented examples — never real secrets.
* Detected values are intended to be masked in output rather than printed in full.
* Removing a secret from the current version of a file does not remove it from Git history; a leaked credential should always be treated as compromised and rotated.

## Limitations

* Regex-based detection cannot catch every possible secret format.
* Entropy detection is heuristic and can produce false positives or miss low-entropy secrets.
* Detection quality depends heavily on tuned thresholds and maintained pattern lists.
* No scanner can guarantee 100% detection coverage.
* Scanning existing Git history for secrets already committed in the past is a possible future extension and is not part of the current scope.

## Future Improvements

Potential extensions include:

* Git history scanning
* JSON output
* SARIF output
* Custom user-defined regex rules
* Performance optimizations for large repositories

## Contributors

* **Huma** — Detection Engine: pattern matching, entropy analysis, and false-positive reduction
* **Haseeb** — CLI & Integration: command-line interface, configuration, Git hooks, and GitHub Actions

## License

This project is licensed under the [MIT License](LICENSE).