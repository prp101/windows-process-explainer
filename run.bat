@echo off
setlocal

if not exist ".venv" (
    echo [setup] Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo ERROR: python not found. Install from https://python.org
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat

echo [setup] Checking dependencies...
pip install -q -r requirements.txt

echo [start] Launching Windows Process Killer...
python main.py

endlocal
