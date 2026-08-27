from pathlib import Path
import sys

HOOK_PATH = Path(".git/hooks/pre-commit")


def install():
    if HOOK_PATH.exists():
        print("A pre-commit hook already exists. Nothing was changed.")
        return

    project_dir = Path(__file__).resolve().parent
    python_path = Path(sys.executable)
    hook_script = project_dir / "pre_commit_hook.py"

    hook_content = (
        "#!/bin/sh\n"
        f'"{python_path}" "{hook_script}"\n'
    )

    HOOK_PATH.write_text(hook_content, encoding="utf-8")

    try:
        HOOK_PATH.chmod(0o755)
    except OSError:
        pass

    print("Pre-commit hook installed successfully.")


if __name__ == "__main__":
    install()