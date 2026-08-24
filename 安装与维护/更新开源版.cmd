@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\install.ps1" -Action Update
if errorlevel 1 pause
endlocal
