@echo off
setlocal
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
"%PS%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0..\scripts\start_all.ps1" -Action Stop -Root "%~dp0.."
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
