@echo off
REM ═══════════════════════════════════════════════════════
REM  PC_SECIO_App  —  Build EXE with PyInstaller
REM  Run this to create a standalone .exe to share
REM ═══════════════════════════════════════════════════════
cd /d "%~dp0"

echo.
echo  Building PC_SECIO standalone EXE...
echo.

python -m pip install pyinstaller --quiet
python -m pip install psutil --quiet

pyinstaller PC_SECIO_App.spec --clean --noconfirm

echo.
if exist "dist\PC_SECIO_App.exe" (
    echo  ╔══════════════════════════════════════════════╗
    echo  ║  SUCCESS! Your EXE is ready:                 ║
    echo  ║  dist\PC_SECIO_App.exe                       ║
    echo  ║                                              ║
    echo  ║  Share this single file with anyone.         ║
    echo  ║  No Python install needed on their PC.       ║
    echo  ╚══════════════════════════════════════════════╝
) else (
    echo  [ERROR] Build failed. Check output above for errors.
)
echo.
pause
