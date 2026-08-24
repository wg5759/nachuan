@echo off
setlocal
chcp 65001 >nul
echo 将从 Gyan 官方固定地址下载并逐字节校验 FFmpeg 8.0.1 ZIP。
echo 只会解出 ffmpeg.exe、ffprobe.exe、LICENSE、README.txt；不会解出 ffplay.exe。
choice /C YN /N /M "继续吗？[Y/N] "
if errorlevel 2 exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0准备FFmpeg构建输入.ps1" -Download -Replace
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" echo 准备失败，正式打包仍会故障关闭。
pause
exit /b %RC%
