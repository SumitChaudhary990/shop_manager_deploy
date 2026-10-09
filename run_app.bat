@echo off
title Shop Management System
echo ===================================================
echo   Starting Shop Management System...
echo ===================================================
echo.

:: Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in your PATH!
    echo Please install Python 3.9+ from https://www.python.org
    pause
    exit /b 1
)

:: Install/Verify requirements
echo [*] Checking dependencies...
pip install -r requirements.txt --quiet

:: Launch Application
echo [*] Starting web server on http://127.0.0.1:5000 ...
echo [*] Access from local network: http://[YOUR-PC-IP]:5000
echo [*] Press Ctrl+C to stop the server.
echo.

python app.py
pause
