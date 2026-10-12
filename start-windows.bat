@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================================
echo   mihomo 旁路网关管理面板 (Windows 真实模式一键启动)
echo ========================================================
start "" "http://127.0.0.1:8090"
python -u app\server.py
pause
