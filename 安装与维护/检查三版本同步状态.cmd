@echo off
setlocal
set "ROOT=%~dp0.."
if exist "%ROOT%\.venv\Scripts\python.exe" (
  "%ROOT%\.venv\Scripts\python.exe" -I -B -X utf8 "%ROOT%\scripts\verify_distribution_contract.py" --root "%ROOT%"
) else (
  py -3 -I -B -X utf8 "%ROOT%\scripts\verify_distribution_contract.py" --root "%ROOT%"
)
pause
endlocal
