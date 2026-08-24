@echo off
chcp 65001 >nul
setlocal
set "ROOT=%~dp0.."
set "PYTHON=%ROOT%\.venv\Scripts\python.exe"
set "WATCHER=%ROOT%\scripts\watch_updates.py"

if not exist "%PYTHON%" (
  echo [ERROR] 项目 Python 环境不存在：%PYTHON%
  echo 请先按本目录 README 的开发环境说明恢复锁定环境。
  pause
  exit /b 2
)
if not exist "%WATCHER%" (
  echo [ERROR] 更新巡检脚本不存在：%WATCHER%
  pause
  exit /b 2
)

pushd "%ROOT%" >nul || exit /b 2
"%PYTHON%" "%WATCHER%"
set "RC=%ERRORLEVEL%"
popd >nul

echo.
echo 巡检结束，报告位于：%ROOT%\data\update_report_YYYYMMDD.md
echo 这只是只读报告，不会安装或升级任何组件。退出码：%RC%
pause
exit /b %RC%
