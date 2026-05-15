#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "PyInstaller is not installed. Installing into the active Python environment..."
  python3 -m pip install pyinstaller
fi

pyinstaller \
  --noconfirm \
  --clean \
  --name ids-sentinel-terminal \
  --add-data "README.md:." \
  --collect-data ids_app \
  --collect-submodules ids_app \
  ids_app/product_app.py

echo "Native build output: dist/ids-sentinel-terminal"
