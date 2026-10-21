@echo off
REM Fetch all spending transactions for a Bitcoin address (transactions where address appears as INPUT)
REM Save raw transaction hex data to JSON file

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
if not exist "%~dp0fetch_address_inputs.py" (
    echo Error: fetch_address_inputs.py not found in current directory
    echo Expected location: %~dp0fetch_address_inputs.py
    pause
    exit /b 1
)

REM Get address from user
echo Enter Bitcoin address:
set /p ADDRESS=
if "%ADDRESS%"=="" (
    echo Error: No address provided
    pause
    exit /b 1
)

REM Get optional output filename
echo.
echo Enter output JSON filename (press Enter for default):
set /p OUTPUT=

REM Run the script
if "%OUTPUT%"=="" (
    python "%~dp0fetch_address_inputs.py" "%ADDRESS%"
) else (
    python "%~dp0fetch_address_inputs.py" "%ADDRESS%" "%OUTPUT%"
)

if %errorlevel% neq 0 (
    echo.
    echo Error occurred during fetch
    pause
    exit /b 1
)

echo.
echo Press any key to exit...
pause >nul
