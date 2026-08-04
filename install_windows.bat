@echo off
setlocal
cd /d "%~dp0"
echo [1/3] Creating Python virtual environment...
py -3 -m venv hidemyemail-generator\.venv
if errorlevel 1 (
  echo Failed to create venv. Install Python 3.11+ first.
  pause
  exit /b 1
)
echo [2/3] Installing hidemyemail-generator requirements...
hidemyemail-generator\.venv\Scripts\python.exe -m pip install --upgrade pip
hidemyemail-generator\.venv\Scripts\python.exe -m pip install -r hidemyemail-generator\requirements.txt
if errorlevel 1 (
  echo pip install failed.
  pause
  exit /b 1
)
echo [3/3] Done.
echo Next: copy hidemyemail-generator\cookie.txt.example to cookie.txt and paste your iCloud cookie.
pause
