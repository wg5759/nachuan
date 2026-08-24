@echo off
setlocal
cd /d "%~dp0.."
set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" (
  echo ERROR: trusted Windows PowerShell was not found.
  pause
  exit /b 1
)
if not exist "scripts\start_all.ps1" (
  echo ERROR: supervisor script is missing.
  pause
  exit /b 1
)
set GATEWAY_API_KEYS=
set APPROVAL_ADMIN_KEY=
set NACHUAN_ALLOW_ANONYMOUS_LOCAL=
set "NACHUAN_ROOT=%CD%"
"%PS%" -NoProfile -NonInteractive -Command "$p=$PSHOME+'\powershell.exe'; $a=@('-NoProfile','-WindowStyle','Hidden','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Join-Path $env:NACHUAN_ROOT 'scripts\start_all.ps1'),'-Action','Resume','-Scheduled','-Root',$env:NACHUAN_ROOT); Start-Process -WindowStyle Hidden -FilePath $p -ArgumentList $a"
if errorlevel 1 goto :failed
"%PS%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "scripts\start_all.ps1" -Action Status -Root "%CD%"
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
:failed
echo ERROR: secure supervisor startup failed. See data\logs\supervisor.log.
pause
exit /b 1
