@echo off
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0..\scripts\build-local.ps1" lean
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
