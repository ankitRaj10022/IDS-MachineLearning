from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"
BUILD_SRC_DIR = ROOT / "build" / "python-package-src"


def is_python_package_artifact(path: Path) -> bool:
    if path.suffix == ".whl" and path.name.startswith("ids_sentinel_terminal-"):
        return True
    if path.name.startswith(("ids_sentinel_terminal-", "ids-sentinel-terminal-")) and path.name.endswith(".tar.gz"):
        suffix = path.name.split("ids_sentinel_terminal-", 1)[-1] if path.name.startswith("ids_sentinel_terminal-") else path.name.split("ids-sentinel-terminal-", 1)[-1]
        return bool(suffix) and suffix[0].isdigit()
    return False


def clean_previous_outputs() -> None:
    if BUILD_SRC_DIR.exists():
        shutil.rmtree(BUILD_SRC_DIR)
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    for path in DIST_DIR.iterdir():
        if path.is_dir():
            continue
        if not path.name.endswith((".whl", ".tar.gz")):
            continue
        if is_python_package_artifact(path):
            path.unlink()


def stage_sources() -> Path:
    BUILD_SRC_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / "pyproject.toml", BUILD_SRC_DIR / "pyproject.toml")
    shutil.copy2(ROOT / "README.md", BUILD_SRC_DIR / "README.md")
    if (ROOT / "MANIFEST.in").exists():
        shutil.copy2(ROOT / "MANIFEST.in", BUILD_SRC_DIR / "MANIFEST.in")
    shutil.copytree(
        ROOT / "ids_app",
        BUILD_SRC_DIR / "ids_app",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )
    (BUILD_SRC_DIR / "setup.py").write_text("from setuptools import setup\nsetup()\n", encoding="utf-8", newline="\n")
    return BUILD_SRC_DIR


def run_setup(stage_dir: Path, command: str) -> None:
    subprocess.run(
        [sys.executable, "setup.py", command, "--dist-dir", str(DIST_DIR)],
        cwd=stage_dir,
        check=True,
    )


def main() -> int:
    clean_previous_outputs()
    stage_dir = stage_sources()
    run_setup(stage_dir, "bdist_wheel")
    run_setup(stage_dir, "sdist")
    for path in sorted(DIST_DIR.iterdir()):
        if path.is_file() and is_python_package_artifact(path):
            size_mb = path.stat().st_size / (1024 * 1024)
            print(f"{path.relative_to(ROOT)} ({size_mb:.2f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
