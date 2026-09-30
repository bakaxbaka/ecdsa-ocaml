@echo off
REM ============================================================================
REM  start-console.cmd  --  DOUBLE-CLICK THIS FILE.
REM
REM  Why this file exists:
REM    .ps1 has NO file association on this machine (verified: `assoc .ps1` returns
REM    "File association not found for extension .ps1"). So double-clicking
REM    run-server.ps1 does not run it -- Windows treats it as a document and offers
REM    to open or download it, which is exactly the behaviour that led here.
REM
REM    .cmd IS associated with the command processor, so double-clicking this file
REM    runs it. This wrapper does nothing except invoke run-server.ps1 correctly:
REM    bypassing the execution policy for this one invocation, and holding the
REM    window open if anything fails so the error is readable instead of the
REM    window vanishing.
REM ============================================================================

setlocal
cd /d "%~dp0"

REM Prefer PowerShell 7 (pwsh) and fall back to Windows PowerShell 5.1.
where pwsh >nul 2>nul
if %ERRORLEVEL%==0 (
  set "PS=pwsh"
) else (
  set "PS=powershell"
)

echo.
echo   ecdsa-ocaml analysis console
echo   ============================
echo   shell: %PS%
echo.

REM -NoProfile   : do not source a user profile that could alter PATH or aliases
REM -ExecutionPolicy Bypass : this script is local and unsigned; the default policy
REM                           would otherwise refuse to run it
%PS% -NoProfile -NoLogo -ExecutionPolicy Bypass -File "%~dp0run-server.ps1" %*

set "RC=%ERRORLEVEL%"

if not "%RC%"=="0" (
  echo.
  echo   The launcher exited with code %RC%.
  echo   The messages above explain why. Common causes:
  echo     - dune or npm is not on PATH
  echo     - the port is already in use
  echo     - a build error in lib/ or web/
  echo.
  pause
)

endlocal
