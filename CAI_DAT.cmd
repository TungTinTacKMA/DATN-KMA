@echo off
cd /d "%~dp0"
py -3.11 -m venv .venv
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto fail
".venv\Scripts\python.exe" -m pip install --no-deps -e .
if errorlevel 1 goto fail
echo Installation complete. Run MO_SAN_PHAM.cmd.
pause
exit /b 0
:fail
echo Installation failed. Check Python 3.11 and the error above.
pause
exit /b 1
