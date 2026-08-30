import math
import re
from pathlib import Path

# constants for regex patterns
TEMPLATE_PLACEHOLDER_PATTERN = re.compile(
    r"^\{[A-Za-z_][A-Za-z0-9_]*\}$"
)
AWS_ACCESS_KEY_PATTERN = re.compile(
    r"AKIA[A-Z0-9]{16}"
)
GITHUB_TOKEN_PATTERN = re.compile(
    r"ghp_[A-Za-z0-9_]{20,}"
)
GITHUB_FINE_GRAINED_TOKEN_PATTERN = re.compile(
    r"github_pat_[A-Za-z0-9_]{20,}"
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-{5}BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-{5}"
)
GENERIC_SECRET_PATTERN = re.compile(
    r'(api_key|token|secret|password)\s*[=:]\s*["\']([^"\']+)["\']',
    re.IGNORECASE # case insensitive
)
JWT_PATTERN = re.compile(
    r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
)

MIN_SECRET_LENGTH = 8 
# minimum entropy needed for generic secret detection.
ENTROPY_THRESHOLD = 3.0 
# 1024 bytes = 1 KB
# 1024 KB    = 1 MB
# 5 × 1024 × 1024
# = 5,242,880 bytes
# = 5 MB
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

DEFAULT_EXCLUDED_DIRS = { # directories to exclude from scanning by default
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "vendor",
}

# all functions before scan_file() are helper functions

def calculate_entropy(text):
    if not text:
        return 0.0

    char_count = {}

    for char in text:
        if char in char_count:
            char_count[char] += 1
        else:
            char_count[char] = 1

    entropy = 0

    for char in char_count:
        # probability is the frequency of the character divided by the total number of characters
        probability = char_count[char]/len(text)
        # entropy is calculated using the formula: -p * log2(p)
        entropy_part = -probability * math.log2(probability)
        # add the entropy part to the total entropy
        entropy += entropy_part

    return entropy

# conservative built-in placeholders commonly used in examples or templates.
# exact matching is used to reduce false positives without suppressing real secrets
# that merely contain words like "test" or "example".
PLACEHOLDER_VALUES = {
    "your_api_key_here",
    "your_token_here",
    "your_secret_here",
    "your_password_here",
    "changeme",
    "replace_me",
    "example_secret",
    "example_token",
    "dummy_secret",
}

def is_placeholder(value):
    return (
        value.lower() in PLACEHOLDER_VALUES
        or TEMPLATE_PLACEHOLDER_PATTERN.fullmatch(value) is not None
    )

def is_allowlisted(value, allowlist):
    if not allowlist:
        return False

    return value in allowlist

def is_excluded_path(path, excluded_dirs): 
    if not excluded_dirs:
        return False

    path = Path(path)

    return any(part in excluded_dirs for part in path.parts)

def is_binary_file(path):
    try:
        # read the first 1024 bytes of the file
        with open(path, "rb") as file:
            chunk = file.read(1024)
        return b"\x00" in chunk

    except (PermissionError, FileNotFoundError):
        return False

def is_file_too_large(path):
    # check if the file is larger than 5 MB
    try:
        # stat().st_size gives the file's size in bytes without reading the whole file.
        return Path(path).stat().st_size > MAX_FILE_SIZE
    except (FileNotFoundError, PermissionError):
        return False

def scan_file(path, allowlist=None):
    findings = []
    # skip files larger than 5 MB
    if is_file_too_large(path):
        return []
    # skip binary files
    if is_binary_file(path):
        return []
    # error handling for file reading
    try:
    # read the contents of the file
        with open(path, "r", encoding="utf-8") as file:
            file_content = file.read()
            
            for line_num, line in enumerate(file_content.splitlines(), start=1):
                # check for AWS access keys in the line
                for aws_match in AWS_ACCESS_KEY_PATTERN.finditer(line):
                    aws_value = aws_match.group(0)

                    if not is_allowlisted(aws_value, allowlist):
                        findings.append({
                            "file": str(path),
                            "line": line_num,
                            "type": "AWS Access Key",
                            "severity": "HIGH"
                        })
                # check for GitHub tokens in the line
                for github_match in GITHUB_TOKEN_PATTERN.finditer(line):
                    github_value = github_match.group(0)

                    if not is_allowlisted(github_value, allowlist):
                        findings.append({
                            "file": str(path),
                            "line": line_num,
                            "type": "GitHub Token",
                            "severity": "HIGH"
                        })
                # check for GitHub fine-grained tokens in the line
                for github_fine_grained_match in GITHUB_FINE_GRAINED_TOKEN_PATTERN.finditer(line):
                    github_fine_grained_value = github_fine_grained_match.group(0)

                    if not is_allowlisted(github_fine_grained_value, allowlist):
                        findings.append({
                            "file": str(path),
                            "line": line_num,
                            "type": "GitHub Fine-Grained Token",
                            "severity": "HIGH"
                        })
                # check for private keys in the line
                if PRIVATE_KEY_PATTERN.search(line):
                    findings.append({
                        "file": str(path),
                        "line": line_num,
                        "type": "Private Key",
                        "severity": "HIGH"
                    })
                # check for JWT tokens in the line
                for jwt_match in JWT_PATTERN.finditer(line):
                    jwt_value = jwt_match.group(0)

                    if not is_allowlisted(jwt_value, allowlist):
                        findings.append({
                            "file": str(path),
                            "line": line_num,
                            "type": "JWT Token",
                            "severity": "HIGH"
                        })
                # check for generic secrets in the line
                for match in GENERIC_SECRET_PATTERN.finditer(line):
                    # extract the secret value from the match
                    secret_value = match.group(2)
                    # skip placeholder values
                    if is_placeholder(secret_value):
                        continue
                    # skip allowlisted values
                    if is_allowlisted(secret_value, allowlist):
                        continue
                    # avoid duplicate findings when a specific detector already matches
                    if (
                        AWS_ACCESS_KEY_PATTERN.fullmatch(secret_value)
                        or GITHUB_TOKEN_PATTERN.fullmatch(secret_value)
                        or GITHUB_FINE_GRAINED_TOKEN_PATTERN.fullmatch(secret_value)
                        or JWT_PATTERN.fullmatch(secret_value)
                    ):
                        continue
                    # reduces false positives using minimum length and entropy
                    if len(secret_value) < MIN_SECRET_LENGTH:
                        continue

                    entropy = calculate_entropy(secret_value)

                    if entropy < ENTROPY_THRESHOLD:
                        continue

                    findings.append({
                        "file": str(path),
                        "line": line_num,
                        "type": match.group(1).upper(),
                        "severity": "MEDIUM"
                    })
                        
        return findings

    except (UnicodeDecodeError, PermissionError, FileNotFoundError):
        return []

def scan_path(path, allowlist=None, excluded_dirs=None):
    path = Path(path)
    # combine the default excluded directories with the user-specified excluded directories
    effective_excluded_dirs = DEFAULT_EXCLUDED_DIRS | set(excluded_dirs or [])
    # skip the supplied path itself if it belongs to an excluded directory
    if is_excluded_path(path, effective_excluded_dirs):
        return []
    # check if the path is a file or directory
    if path.is_file():
        return scan_file(path, allowlist)

    if path.is_dir():
        findings = []
        # iterate through all files in the directory and its subdirectories recursively
        for file_path in path.rglob("*"):
            if is_excluded_path(file_path, effective_excluded_dirs):
                continue

            if file_path.is_file():
                findings.extend(scan_file(file_path, allowlist))

        return findings
    # if the path is neither a file nor a directory, return an empty list
    return []

