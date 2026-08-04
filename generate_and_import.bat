@echo off
setlocal
cd /d "%~dp0"
if "%~1"=="" (
  echo Usage: generate_and_import.bat COUNT [ADMIN_KEY] [API_URL] [SUCCESS_DELAY] [FAILURE_DELAY]
  echo Example: generate_and_import.bat 1
  echo Example: generate_and_import.bat 10 adm_xxx http://127.0.0.1:8765 780 3900
  pause
  exit /b 1
)
set "COUNT=%~1"
set "ADMIN_KEY=%~2"
set "API_URL=%~3"
set "SUCCESS_DELAY=%~4"
set "FAILURE_DELAY=%~5"
if "%API_URL%"=="" set "API_URL=http://127.0.0.1:8765"
if "%SUCCESS_DELAY%"=="" set "SUCCESS_DELAY=100"
if "%FAILURE_DELAY%"=="" set "FAILURE_DELAY=120"
set "ADMIN_ARG="
if not "%ADMIN_KEY%"=="" set "ADMIN_ARG=--admin-key %ADMIN_KEY%"
"%~dp0hidemyemail-generator\.venv\Scripts\python.exe" "%~dp0icloud-code-api\generate_and_import.py" --count %COUNT% --success-delay %SUCCESS_DELAY% --failure-delay %FAILURE_DELAY% --api-url %API_URL% %ADMIN_ARG%
set "EXIT_CODE=%ERRORLEVEL%"
pause
exit /b %EXIT_CODE%
