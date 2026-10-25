@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run CAI_DAT.cmd first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" verify_package.py --predictions
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m pytest -q
if errorlevel 1 goto fail
pause
exit /b 0
:fail
echo Verification failed. Read the error above.
pause
exit /b 1
