from pathlib import Path
import stat

HOOK_PATH = Path(".git/hooks/pre-commit")

HOOK_CONTENT = "#!/bin/sh\npython pre_commit_hook.py\n"


def install():
    HOOK_PATH.write_text(HOOK_CONTENT)
    HOOK_PATH.chmod(HOOK_PATH.stat().st_mode | stat.S_IEXEC)
    print("Pre-commit hook installed successfully.")


if __name__ == "__main__":
    install()