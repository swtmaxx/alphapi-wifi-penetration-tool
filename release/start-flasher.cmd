@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel% equ 0 (
  start "" "http://localhost:8000/alphapi-one-s-web-flasher.html"
  py -3 -m http.server 8000 --bind 127.0.0.1
  exit /b
)

where python >nul 2>nul
if %errorlevel% equ 0 (
  start "" "http://localhost:8000/alphapi-one-s-web-flasher.html"
  python -m http.server 8000 --bind 127.0.0.1
  exit /b
)

echo Python 3 not found. Install Python 3, then run this file again.
pause
