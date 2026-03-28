@echo off
REM ═══════════════════════════════════════════════════════
REM  PC_SECIO_App  —  Setup & Run Script (FIXED)
REM  %~dp0 ensures we always run from THIS file's folder,
REM  not System32 or wherever you launched from.
REM ═══════════════════════════════════════════════════════
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════╗
echo  ║   PC_SECIO  Setup ^& Launcher         ║
echo  ╚══════════════════════════════════════╝
echo.

REM Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+ from https://python.org
    echo         Make sure to check "Add Python to PATH" during install!
    pause
    exit /b 1
)

echo [1/3] Python found. Installing dependencies...
python -m pip install --upgrade pip --quiet
python -m pip install psutil --quiet

echo [2/3] Dependencies installed.
echo [3/3] Launching PC_SECIO...
echo.
echo  NOTE: Some connections require admin rights.
echo  If you see limited results, right-click this
echo  file and choose "Run as Administrator".
echo.

python "%~dp0pc_secio.py"
pause
