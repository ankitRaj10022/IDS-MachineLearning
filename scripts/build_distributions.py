from __future__ import annotations

import argparse
import os
import shutil
import stat
import tarfile
import zipapp
import zipfile
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "ids-firewall"
DIST_DIR = ROOT / "dist"
PACKAGE_NAME = "ids-firewall-tool"


def copy_tree(source: Path, target: Path) -> None:
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(
        source,
        target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
    )


def write_text(path: Path, text: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    if executable:
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def prepare_stage(include_exports: bool = False) -> Path:
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True)

    app_src = BUILD_DIR / "pyz_src"
    copy_tree(ROOT / "ids_app", app_src / "ids_app")
    zipapp.create_archive(app_src, BUILD_DIR / "ids-firewall.pyz", main="ids_app.product_app:main", interpreter="/usr/bin/env python3")

    for filename in ("README.md", "kddtrain.csv", "kddtest.csv"):
        source = ROOT / filename
        if source.exists():
            shutil.copy2(source, BUILD_DIR / filename)

    product_dir = BUILD_DIR / "automation" / "product"
    (product_dir / "exports").mkdir(parents=True, exist_ok=True)
    (product_dir / "imports").mkdir(parents=True, exist_ok=True)
    (product_dir / "cache" / "indexes").mkdir(parents=True, exist_ok=True)
    (product_dir / "cache" / "commands").mkdir(parents=True, exist_ok=True)

    for filename in ("self_learning_model.json", "iocs.json"):
        source = ROOT / "automation" / "product" / filename
        if source.exists():
            shutil.copy2(source, product_dir / filename)

    if include_exports and (ROOT / "automation" / "product" / "exports").exists():
        copy_tree(ROOT / "automation" / "product" / "exports", product_dir / "exports")

    write_launchers(BUILD_DIR)
    write_text(BUILD_DIR / "VERSION.txt", f"build_time={datetime.now().isoformat(timespec='seconds')}\n")
    shutil.rmtree(app_src)
    return BUILD_DIR


def write_launchers(stage: Path) -> None:
    write_text(
        stage / "ids-firewall.cmd",
        """@echo off
setlocal
cd /d "%~dp0"
set "IDS_PRODUCT_HOME=%CD%"
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 "%~dp0ids-firewall.pyz" %*
  exit /b %ERRORLEVEL%
)
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python "%~dp0ids-firewall.pyz" %*
  exit /b %ERRORLEVEL%
)
echo Python 3 was not found. Install Python 3 and rerun this command. 1>&2
exit /b 1
""",
    )
    write_text(
        stage / "ids-firewall-gui.cmd",
        """@echo off
setlocal
cd /d "%~dp0"
call "%~dp0ids-firewall.cmd" gui
""",
    )
    write_text(
        stage / "ids-firewall",
        """#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export IDS_PRODUCT_HOME="$DIR"
exec python3 "$DIR/ids-firewall.pyz" "$@"
""",
        executable=True,
    )
    write_text(
        stage / "ids-firewall-gui",
        """#!/usr/bin/env sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export IDS_PRODUCT_HOME="$DIR"
exec python3 "$DIR/ids-firewall.pyz" gui "$@"
""",
        executable=True,
    )
    write_text(
        stage / "INSTALL.txt",
        """IDS Firewall Tool

Windows:
  ids-firewall.cmd status
  ids-firewall-gui.cmd

macOS/Linux:
  ./ids-firewall status
  ./ids-firewall-gui

Read README.md for the full manual.
""",
    )


def make_zip(stage: Path, target: Path) -> None:
    if target.exists():
        target.unlink()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in stage.rglob("*"):
            archive.write(path, path.relative_to(stage.parent))


def make_tar(stage: Path, target: Path) -> None:
    if target.exists():
        target.unlink()
    with tarfile.open(target, "w:gz") as archive:
        archive.add(stage, arcname=stage.name)


def build_archives(include_exports: bool = False) -> list[Path]:
    stage = prepare_stage(include_exports=include_exports)
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    targets = [
        DIST_DIR / f"{PACKAGE_NAME}-windows.zip",
        DIST_DIR / f"{PACKAGE_NAME}-macos.tar.gz",
        DIST_DIR / f"{PACKAGE_NAME}-linux.tar.gz",
        DIST_DIR / f"{PACKAGE_NAME}-portable.zip",
    ]
    make_zip(stage, targets[0])
    make_tar(stage, targets[1])
    make_tar(stage, targets[2])
    make_zip(stage, targets[3])
    return targets


def main() -> int:
    parser = argparse.ArgumentParser(description="Build cross-platform IDS Firewall Tool archives.")
    parser.add_argument("--include-exports", action="store_true", help="Bundle generated analysis reports too.")
    args = parser.parse_args()
    targets = build_archives(include_exports=args.include_exports)
    for target in targets:
        size_mb = target.stat().st_size / (1024 * 1024)
        print(f"{target.relative_to(ROOT)} ({size_mb:.2f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
