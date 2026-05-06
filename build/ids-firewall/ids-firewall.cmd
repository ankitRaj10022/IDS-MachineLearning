@echo off
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
