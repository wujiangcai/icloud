@echo off
setlocal
cd /d "%~dp0"
if not exist "data\platform" mkdir "data\platform"
if "%PLATFORM_HOST%"=="" set "PLATFORM_HOST=127.0.0.1"
if "%PLATFORM_PORT%"=="" set "PLATFORM_PORT=8766"
echo Starting iCloud Code Platform at http://%PLATFORM_HOST%:%PLATFORM_PORT%/
echo Press Ctrl+C to stop the API. Run platform_worker.py in a second terminal for IMAP polling.
python platform_app.py
