@echo off
cd /d D:\ecdsa-ocaml
dune build
echo Build completed with exit code: %ERRORLEVEL%
pause
