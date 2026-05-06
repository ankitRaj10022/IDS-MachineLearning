#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v pyinstaller >/dev/null 2>&1; then
  echo "PyInstaller is not installed. Installing into the active Python environment..."
  python3 -m pip install pyinstaller
fi

export IDS_PRODUCT_HOME="${ROOT_DIR}"
pyinstaller \
  --noconfirm \
  --clean \
  --name ids-sentinel-terminal \
  --add-data "kddtrain.csv:." \
  --add-data "kddtest.csv:." \
  --add-data "README.md:." \
  --add-data "automation/product/self_learning_model.json:automation/product" \
  --collect-submodules ids_app \
  ids_app/product_app.py

echo "Native build output: dist/ids-sentinel-terminal"
