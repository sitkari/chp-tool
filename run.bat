@echo off
rem Run the GUI straight from sources (no console window).
cd /d "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 (
    start "" python chp-gui.py %*
) else (
    start "" pythonw chp-gui.py %*
)
