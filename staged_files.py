import subprocess


def get_staged_files():
    # Ask Git for files currently staged for commit.
    # --name-status gives us both the file status and its filename.
    result = subprocess.run(
        ["git", "diff", "--staged", "--name-status"],
        capture_output=True,
        text=True
    )

    staged = []

    for line in result.stdout.splitlines():
        # Ignore empty lines in Git's output.
        if not line.strip():
            continue

        parts = line.split("\t")
        status = parts[0]

        # For renamed files, Git returns both the old and new filename.
        # Using the last part gives us the filename that currently exists.
        filename = parts[-1]

        # Deleted files are skipped because there is no file left to scan.
        if status.startswith("D"):
            continue

        # Keep the current filename so it can be scanned later.
        staged.append(filename)

    return staged




