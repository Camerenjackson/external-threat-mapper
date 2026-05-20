@echo off
cd /d "%~dp0"
where python >nul 2>&1
if %ERRORLEVEL%==0 (
  python "%~dp0launcher\launch_gui.py"
  exit /b %ERRORLEVEL%
)
powershell -NoProfile -ExecutionPolicy Bypass -STA -File "%~dp0Scripts\Start-ExternalThreatMapper.ps1"
exit /b %ERRORLEVEL%
