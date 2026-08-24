@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0..\install.ps1" -Action Uninstall
pause
endlocal
