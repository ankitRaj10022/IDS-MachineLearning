$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $root

if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "PyInstaller is not installed. Installing into the active Python environment..."
    python -m pip install pyinstaller
}

$env:IDS_PRODUCT_HOME = $root
pyinstaller `
  --noconfirm `
  --clean `
  --name ids-firewall `
  --add-data "kddtrain.csv;." `
  --add-data "kddtest.csv;." `
  --add-data "README.md;." `
  --add-data "automation\product\self_learning_model.json;automation\product" `
  --collect-submodules ids_app `
  ids_app\product_app.py

Write-Host "Native build output: dist\ids-firewall"
