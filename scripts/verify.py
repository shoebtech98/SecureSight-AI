"""Repository verification entry point for SecureSight AI."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BACKEND_TEST_MODULES = ["backend.tests.test_audit_suite", "backend.tests.test_gemini"]
FRONTEND_DIR = ROOT / "frontend"


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    display = " ".join(command)
    print(f"\n$ {display}  (cwd={cwd})")
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> int:
    node_override = os.environ.get("SECURESIGHT_NODE")
    npm = shutil.which("npm") if not node_override else None
    if node_override and not Path(node_override).is_file():
        print("SECURESIGHT_NODE does not point to a Node.js executable.")
        return 1
    if npm is None and not node_override:
        print("npm was not found on PATH; install Node.js before verification.")
        return 1

    backend_env = os.environ.copy()
    with tempfile.TemporaryDirectory(prefix="securesight-test-") as temp_dir:
        test_db = Path(temp_dir) / "verify.db"
        backend_env["DATABASE_URL"] = f"sqlite:///{test_db.as_posix()}"
        run(
            [
                sys.executable,
                "-W",
                "error::DeprecationWarning",
                "-m",
                "unittest",
                *BACKEND_TEST_MODULES,
            ],
            cwd=ROOT,
            env=backend_env,
        )

    if node_override:
        run([node_override, "node_modules/oxlint/bin/oxlint"], cwd=FRONTEND_DIR)
        run([node_override, "node_modules/vite/bin/vite.js", "build"], cwd=FRONTEND_DIR)
    else:
        run([npm, "run", "lint"], cwd=FRONTEND_DIR)
        run([npm, "run", "build"], cwd=FRONTEND_DIR)
    print("\nRepository verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
