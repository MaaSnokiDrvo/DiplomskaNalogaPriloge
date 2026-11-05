@echo off
REM Namestitveni skript grafičnega vmesnika NetSentinel IDS
REM Samodejno pripravi okolje Python in namesti odvisnosti

echo.
echo ========================================
echo NetSentinel IDS - GUI Setup
echo ========================================
echo.

REM Preveri, ali je Python nameščen
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo [1/4] Checking Python version...
python --version

echo.
echo [2/4] Creating virtual environment...
if exist venv (
    echo Virtual environment already exists - skipping
) else (
    python -m venv venv
    echo Virtual environment created
)

echo.
echo [3/4] Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo [4/4] Installing dependencies...
pip install -r requirements.txt

echo.
echo ========================================
echo Setup complete!
echo ========================================
echo.
echo To run the GUI dashboard:
echo   1. Make sure NetSentinel IDS C++ backend is running
echo      (should be listening on http://localhost:8080)
echo   2. Run: python main.py
echo.
echo Or directly activate the environment:
echo   venv\Scripts\activate
echo   python main.py
echo.
pause
