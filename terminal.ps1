$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$env:IDS_PRODUCT_HOME = $root

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 -X utf8 -m ids_app.product_app @args
    exit $LASTEXITCODE
}

if (Get-Command python -ErrorAction SilentlyContinue) {
    & python -X utf8 -m ids_app.product_app @args
    exit $LASTEXITCODE
}

Write-Error "Python was not found. Install Python 3, then run terminal.ps1 again."
exit 1
