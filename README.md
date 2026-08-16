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

The CLI, Git pre-commit hook, and GitHub Action are designed to call the same underlying scanner rather than duplicating detection logic.

The scanner exposes a simple interface:

```python
scan_path(path)
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

The scanner is designed to reduce false positives using several safeguards:

* Minimum string length
* Allowlists for approved values
* Exclusion of common placeholder or example credentials
* Configurable detection thresholds

## Installation

Clone the repository:

```bash
git clone https://github.com/haseeb2006-bit/credential-leak-scanner.git
cd credential-leak-scanner
```

Requires Python 3.10 or later.

## Usage

The scanner can be used from the command line:

```bash
scanner scan example.py
```

Example output:

```text
[HIGH] AWS Access Key detected
File: example.py
Line: 5
```

The CLI currently supports scanning a single file. Support for scanning entire directories and additional configuration options is planned.

## Configuration

The scanner is intended to support a configuration file allowing users to customize:

* Entropy detection threshold
* Excluded files and directories
* Allowlisted values

## Git Pre-Commit Integration

The project is being developed to include a Git pre-commit hook that scans staged files before a commit is allowed to complete.

This provides protection at the earliest point in the development workflow and helps prevent secrets from entering version control.

## GitHub Actions

A GitHub Actions workflow is planned to automatically scan Pull Requests.

This provides a CI-level safety net in addition to local pre-commit protection.

## Testing

The project includes automated tests covering detection logic and CLI behavior, with Git hook and CI integration tests planned as those features are completed.

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
* **Haseeb** — CLI & Integration: command-line interface, Git hooks, GitHub Actions, and configuration

## License

This project is licensed under the [MIT License](LICENSE).