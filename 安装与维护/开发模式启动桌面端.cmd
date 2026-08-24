@echo off
setlocal
REM DEVELOPMENT ONLY. This source launcher is never a production entry.
if /I not "%NACHUAN_ENABLE_DESKTOP_DEV%"=="I_UNDERSTAND_DEV_ONLY" (
  echo BLOCKED: source-tree Electron dev mode is not a production launcher.
  echo Set NACHUAN_ENABLE_DESKTOP_DEV=I_UNDERSTAND_DEV_ONLY only for development.
  pause
  exit /b 2
)
cd /d "%~dp0..\desktop"
if not exist "package.json" (
  echo ERROR: desktop\package.json was not found.
  pause
  exit /b 1
)
echo Starting Nachuan desktop in development mode...
echo Keep this window open; closing it stops the desktop process.
call npm run dev
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
