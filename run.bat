@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

start "LR2 Server" cmd /k python server.py
ping -n 2 127.0.0.1 >nul

python client.py %*
