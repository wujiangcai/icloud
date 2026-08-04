@echo off
setlocal
cd /d "%~dp0"
if not exist "hidemyemail-generator\.venv\Scripts\python.exe" (
  echo Python virtual environment not found. Run install_windows.bat first.
  pause
  exit /b 1
)
"hidemyemail-generator\.venv\Scripts\python.exe" "hidemyemail-generator\refresh_cookie.py" --headed --keep-alive --interval-seconds 300
set "EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %EXIT_CODE%
