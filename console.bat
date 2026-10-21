@echo off
REM Console interface for ECDSA signature analysis pipeline

setlocal

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Python not found in PATH
    echo Please install Python 3.6+ and add it to your PATH
    pause
    exit /b 1
)

REM Check if script exists
if not exist "%~dp0console_interface.py" (
    echo Error: console_interface.py not found in current directory
    echo Expected location: %~dp0console_interface.py
    pause
    exit /b 1
)

python "%~dp0console_interface.py"

pause
