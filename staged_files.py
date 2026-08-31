import subprocess


def get_staged_files():
    # Ask Git for the files currently staged for the next commit.
    result = subprocess.run(
        ["git", "diff", "--staged", "--name-status"],
        capture_output=True,
        text=True
    )

    # If Git fails, stop instead of treating the failure as an empty scan.
    if result.returncode != 0:
        raise RuntimeError(
            f"Git could not read staged files: {result.stderr.strip()}"
        )

    staged = []

    for line in result.stdout.splitlines():
        if not line.strip():
            continue

        parts = line.split("\t")
        status = parts[0]
        filename = parts[-1]

        # Deleted files have no content left to scan.
        if status.startswith("D"):
            continue

        staged.append(filename)

    return staged


def get_staged_content(filename):
    # Read the exact version of the file stored in Git's staging area.
    # capture_output without text=True gives us raw bytes, so we can
    # detect and handle UTF-16 files instead of silently mangling them.
    result = subprocess.run(
        ["git", "show", f":{filename}"],
        capture_output=True
    )

    # A Git failure here must not be treated as "no secrets found" —
    # it should stop the scan, same as get_staged_files() does above.
    if result.returncode != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

        raise RuntimeError(
            f"Git could not read staged content for '{filename}': {stderr.strip()}"
        )

    raw = result.stdout

    # Windows tools sometimes save files as UTF-16, which would otherwise
    # get garbled and cause real secrets to be missed.
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")

    return raw.decode("utf-8", errors="replace")