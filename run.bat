@echo off
setlocal enabledelayedexpansion

:: ─────────────────────────────────────────────────────────────────
::  PCAP Analyzer — Windows launcher
::  Double-click this file (or run from a command prompt) to start.
:: ─────────────────────────────────────────────────────────────────

:: Move to the script's own directory so relative paths always work
cd /d "%~dp0"

:: ── 1. Verify Python is on PATH ──────────────────────────────────
where python >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: Python was not found on PATH.
    echo  Install Python 3.9 or newer from https://www.python.org/downloads/
    echo  and make sure to tick "Add Python to PATH" during setup.
    echo.
    pause
    exit /b 1
)

:: ── 2. Check Python version ^>= 3.9 ──────────────────────────────
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYVER=%%v
for /f "tokens=1,2 delims=." %%a in ("%PYVER%") do (
    set PYMAJ=%%a
    set PYMIN=%%b
)

if !PYMAJ! LSS 3 goto :version_error
if !PYMAJ! EQU 3 if !PYMIN! LSS 9 goto :version_error
goto :version_ok

:version_error
echo.
echo  ERROR: Python 3.9 or newer is required. Found: %PYVER%
echo  Download the latest Python from https://www.python.org/downloads/
echo.
pause
exit /b 1

:version_ok
echo  Python %PYVER% detected.

:: ── 3. Create virtual environment if not present ─────────────────
if not exist ".venv\Scripts\activate.bat" (
    echo  Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo  ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: ── 4. Activate virtual environment ──────────────────────────────
call .venv\Scripts\activate.bat

:: ── 5. Install / upgrade dependencies ────────────────────────────
echo  Installing dependencies ^(this may take a moment on first run^)...
pip install -q -r requirements.txt
if errorlevel 1 (
    echo  ERROR: pip install failed. Check your internet connection and try again.
    pause
    exit /b 1
)

:: ── 6. Copy .env.example → .env if .env is missing ───────────────
if not exist ".env" (
    echo  Creating .env from .env.example...
    copy ".env.example" ".env" >nul
    echo  NOTE: Edit .env to add your VirusTotal API key ^(optional^).
)

:: ── 7. Create runtime directories ────────────────────────────────
if not exist "uploads" mkdir uploads
if not exist "data"    mkdir data

:: ── 8. Launch ─────────────────────────────────────────────────────
echo.
echo  Starting PCAP Analyzer on http://127.0.0.1:5000
echo  Press Ctrl+C to stop the server.
echo.
python app.py

pause
