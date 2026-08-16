from scanner import scan_path, calculate_entropy, is_placeholder, is_allowlisted, is_excluded_path
from pathlib import Path

def test_scan_path():
    results = scan_path("test_secret.py")
        
    assert len(results) == 6
    
    aws_result = next(
        result for result in results
        if result["type"] == "AWS Access Key"
    )

    github_result = next(
        result for result in results
        if result["type"] == "GitHub Token"
    )

    assert aws_result["line"] == 1
    assert aws_result["severity"] == "HIGH"

    assert github_result["line"] == 2
    assert github_result["severity"] == "HIGH"

    private_key_results = [
        result for result in results
        if result["type"] == "Private Key"
    ]

    assert len(private_key_results) == 2
    # get the lines of the private keys
    private_key_lines = {
        result["line"] for result in private_key_results
    }

    assert private_key_lines == {3, 7}

    for result in private_key_results:
        assert result["severity"] == "HIGH"
    
    fine_grained_result = next(
        result for result in results
        if result["type"] == "GitHub Fine-Grained Token"
    )

    assert fine_grained_result["line"] == 6
    assert fine_grained_result["severity"] == "HIGH"
    
    jwt_result = next(
        result for result in results
        if result["type"] == "JWT Token"
    )

    assert jwt_result["line"] == 10
    assert jwt_result["severity"] == "HIGH"
    
def test_scan_path_recursively_scans_directory(tmp_path):
    # create a nested directory structure with a file containing an AWS access key
    nested_dir = tmp_path/"src"
    nested_dir.mkdir()

    nested_file = nested_dir/"config.py"
    nested_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    results = scan_path(tmp_path)

    assert len(results) == 1
    assert results[0]["type"] == "AWS Access Key"
    assert results[0]["file"] == str(nested_file)

def test_entropy_repeated_characters():
    assert calculate_entropy("AAAA") == 0.0

def test_entropy_unique_characters():
    assert calculate_entropy("ABCD") == 2.0

def test_generic_secret_detection(tmp_path):
    test_file = tmp_path/"config.py"

    test_file.write_text(
        'api_key = "X7pQ2mL9vA4z"',
        encoding="utf-8"
    )

    results = scan_path(test_file)

    assert len(results) == 1
    assert results[0]["type"] == "API_KEY"
    assert results[0]["line"] == 1
    assert results[0]["severity"] == "MEDIUM"

def test_low_entropy_secret_is_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    test_file.write_text(
        'password = "password"',
        encoding="utf-8"
    )

    results = scan_path(test_file)

    assert results == []

def test_placeholder_detection():
    assert is_placeholder("your_api_key_here") is True
    assert is_placeholder("X7testQ9mLp2Xa4") is False
    
def test_placeholder_secret_is_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    test_file.write_text(
        'api_key = "your_api_key_here"',
        encoding="utf-8"
    )

    results = scan_path(test_file)

    assert results == []
    
def test_allowlist_exact_match():
    allowlist = {"APPROVED_TEST_TOKEN"}

    assert is_allowlisted("APPROVED_TEST_TOKEN", allowlist) is True
    assert is_allowlisted("approved_test_token", allowlist) is False
    assert is_allowlisted("OTHER_VALUE", allowlist) is False

def test_allowlisted_secret_is_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    test_file.write_text(
        'api_key = "X7pQ2mL9vA4z"',
        encoding="utf-8"
    )
    # without an allowlist, the generic detector should find it
    results = scan_path(test_file)

    assert len(results) == 1
    assert results[0]["type"] == "API_KEY"
    # explicitly approving that exact value should suppress it
    results = scan_path(
        test_file,
        allowlist={"X7pQ2mL9vA4z"}
    )

    assert results == []

def test_excluded_path_detection():
    excluded_dirs = {"node_modules", ".git"}

    assert is_excluded_path(
        Path("project/node_modules/package/file.js"),
        excluded_dirs
    ) is True

    assert is_excluded_path(
        Path("project/src/config.py"),
        excluded_dirs
    ) is False
    
def test_scan_path_skips_excluded_directory(tmp_path):
    src_dir = tmp_path/"src"
    src_dir.mkdir()

    excluded_dir = tmp_path/"generated"
    excluded_dir.mkdir()

    src_file = src_dir/"config.py"
    src_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    excluded_file = excluded_dir/"package.py"
    excluded_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    results = scan_path(
        tmp_path,
        excluded_dirs={"generated"}
    )

    assert len(results) == 1
    assert results[0]["file"] == str(src_file)
    
def test_allowlisted_aws_key_is_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    aws_key = "AKIAIOSFODNN7EXAMPLE"

    test_file.write_text(
        f'AWS_ACCESS_KEY_ID = "{aws_key}"',
        encoding="utf-8"
    )

    results = scan_path(
        test_file,
        allowlist={aws_key}
    )

    assert results == []

def test_allowlisted_github_token_is_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    github_token = "ghp_FAKE1234567890ABCDEFGHIJK"

    test_file.write_text(
        f'GITHUB_TOKEN = "{github_token}"',
        encoding="utf-8"
    )

    results = scan_path(
        test_file,
        allowlist={github_token}
    )

    assert results == []

def test_allowlisted_github_fine_grained_token_is_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    github_token = "github_pat_FAKE1234567890ABCDEFGHIJK"

    test_file.write_text(
        f'GITHUB_TOKEN = "{github_token}"',
        encoding="utf-8"
    )

    results = scan_path(
        test_file,
        allowlist={github_token}
    )

    assert results == []
    
def test_allowlisted_jwt_is_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    jwt_token = "eyJFAKEHEADER123.eyJFAKEPAYLOAD456.FAKESIGNATURE789"

    test_file.write_text(
        f'JWT_TOKEN = "{jwt_token}"',
        encoding="utf-8"
    )

    results = scan_path(
        test_file,
        allowlist={jwt_token}
    )

    assert results == []
    
def test_default_excluded_directory_is_ignored(tmp_path):
    excluded_dir = tmp_path/"node_modules"
    excluded_dir.mkdir()

    excluded_file = excluded_dir/"package.py"
    excluded_file.write_text(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        encoding="utf-8"
    )

    results = scan_path(tmp_path)

    assert results == []
    
def test_binary_file_is_ignored(tmp_path):
    binary_file = tmp_path/"data.bin"

    binary_file.write_bytes(
        b"\x00\x01AKIAIOSFODNN7EXAMPLE"
    )

    results = scan_path(binary_file)

    assert results == []

def test_very_large_file_is_ignored(tmp_path):
    large_file = tmp_path/"large.txt"

    large_file.write_text(
        'AKIAIOSFODNN7EXAMPLE' + ("A"*(5*1024*1024)),
        encoding="utf-8"
    )

    results = scan_path(large_file)

    assert results == []

def test_empty_file_returns_no_findings(tmp_path):
    empty_file = tmp_path/"empty.txt"
    empty_file.write_text("", encoding="utf-8")

    results = scan_path(empty_file)

    assert results == []


def test_nonexistent_path_returns_no_findings(tmp_path):
    missing_file = tmp_path/"does_not_exist.py"

    results = scan_path(missing_file)

    assert results == []


def test_malformed_secrets_are_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    test_file.write_text(
        """
    AWS_VALUE = "AKIA123"
    GITHUB_VALUE = "ghp_short"
    JWT_VALUE = "eyJonly.two"
    """,
        encoding="utf-8"
    )

    results = scan_path(test_file)

    assert results == []

def test_example_values_are_ignored(tmp_path):
    test_file = tmp_path/"config.py"

    test_file.write_text(
        '''
        api_key = "your_api_key_here"
        token = "example_token"
        secret = "dummy_secret"
        password = "your_password_here"
        ''',
        encoding="utf-8"
    )

    results = scan_path(test_file)

    assert results == []

def test_multiple_aws_keys_on_same_line(tmp_path):
    test_file = tmp_path/"config.py"

    test_file.write_text(
        'KEYS = "AKIAIOSFODNN7EXAMPLE AKIA1234567890ABCDEF"',
        encoding="utf-8"
    )

    results = scan_path(test_file)

    aws_results = [
        result for result in results
        if result["type"] == "AWS Access Key"
    ]

    assert len(aws_results) == 2