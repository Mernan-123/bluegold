@echo off
setlocal
cd /d "%~dp0"
where python >nul 2>&1
if errorlevel 1 (
  echo Install Python 3 and add it to PATH, then run this file again.
  pause
  exit /b 1
)
python -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo Dependency installation failed. Check your internet connection and Python setup.
  pause
  exit /b 1
)
if not defined IP_GEOLOCATION set "IP_GEOLOCATION=1"
python app.py --setup
if errorlevel 1 pause
