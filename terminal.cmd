@echo off
setlocal
cd /d "%~dp0"
set "IDS_PRODUCT_HOME=%CD%"
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 -X utf8 -m ids_app.product_app %*
  exit /b %ERRORLEVEL%
)
where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  python -X utf8 -m ids_app.product_app %*
  exit /b %ERRORLEVEL%
)
echo Python was not found. Install Python 3, then run terminal.cmd again. 1>&2
exit /b 1
