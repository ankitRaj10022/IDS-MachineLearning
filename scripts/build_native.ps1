$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "PyInstaller is not installed. Installing into the active Python environment..."
    python -m pip install pyinstaller
}

pyinstaller `
  --noconfirm `
  --clean `
  --name ids-sentinel-terminal `
  --add-data "README.md;." `
  --collect-data ids_app `
  --collect-submodules ids_app `
  ids_app\product_app.py

Write-Host "Native build output: dist\ids-sentinel-terminal"
