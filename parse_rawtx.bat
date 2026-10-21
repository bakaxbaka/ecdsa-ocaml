@echo off
REM Parse raw Bitcoin transaction - extract r, s signatures and calculate sighash (z)

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
if not exist "%~dp0parse_rawtx.py" (
    echo Error: parse_rawtx.py not found in current directory
    echo Expected location: %~dp0parse_rawtx.py
    pause
    exit /b 1
)

REM Get raw transaction hex from user
echo Enter raw transaction hex:
set /p RAWTX=
if "%RAWTX%"=="" (
    echo Error: No hex provided
    pause
    exit /b 1
)

REM Get optional input index
echo.
echo Enter input index (press Enter for 0):
set /p INPUT_INDEX=
if "%INPUT_INDEX%"=="" set INPUT_INDEX=0

REM Run the script
python "%~dp0parse_rawtx.py" "%RAWTX%" %INPUT_INDEX%

if %errorlevel% neq 0 (
    echo.
    echo Error occurred during parsing
    pause
    exit /b 1
)

echo.
echo Press any key to exit...
pause >nul
