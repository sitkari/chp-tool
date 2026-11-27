@echo off
setlocal
cd /d "%~dp0"

rem Build the single-file GUI executable (PyInstaller).
where python >nul 2>nul
if errorlevel 1 (
    echo Python not found in PATH.
    exit /b 1
)

python -m pip install --quiet --disable-pip-version-check pyinstaller
if errorlevel 1 (
    echo Could not install PyInstaller.
    exit /b 1
)

python -m PyInstaller --noconfirm --clean --onefile --windowed ^
    --name "CHP-Tool" chp-gui.py
if errorlevel 1 (
    echo Build failed.
    exit /b 1
)

echo.
echo Done: %~dp0dist\CHP-Tool.exe
endlocal
