@echo off
REM Batch parse all transactions from a JSON file created by fetch_address_inputs.py
REM Extract r/s signatures for all transactions and output to CSV

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
if not exist "%~dp0batch_parse_address_txs.py" (
    echo Error: batch_parse_address_txs.py not found in current directory
    echo Expected location: %~dp0batch_parse_address_txs.py
    pause
    exit /b 1
)

REM List available JSON files
echo Available JSON files:
dir /b "%~dp0"*.json 2>nul
echo.

REM Get input file from user
echo Enter JSON filename:
set /p INPUT=
if "%INPUT%"=="" (
    echo Error: No file provided
    pause
    exit /b 1
)

REM Check if file exists
if not exist "%~dp0%INPUT%" (
    echo Error: File not found: %INPUT%
    pause
    exit /b 1
)

REM Get optional output filename
echo.
echo Enter output CSV filename (press Enter for default):
set /p OUTPUT=

REM Run the script
if "%OUTPUT%"=="" (
    python "%~dp0batch_parse_address_txs.py" "%~dp0%INPUT%"
) else (
    python "%~dp0batch_parse_address_txs.py" "%~dp0%INPUT%" "%OUTPUT%"
)

if %errorlevel% neq 0 (
    echo.
    echo Error occurred during parsing
    pause
    exit /b 1
)

echo.
echo Press any key to exit...
pause >nul
