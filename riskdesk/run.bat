@echo off
REM RiskDesk launcher for Command Prompt, or for double-clicking in Explorer.
REM PowerShell users can call run.ps1 directly for more options.

setlocal
cd /d "%~dp0"

if not exist "requirements.txt" goto :wrongfolder
if not exist "app\cli.py" goto :wrongfolder

set "VENV_PY=.venv\Scripts\python.exe"

if not exist "%VENV_PY%" (
    echo   Creating virtual environment...
    py -3 -m venv .venv 2>nul
    if errorlevel 1 python -m venv .venv
    if errorlevel 1 goto :nopython
)

echo   Installing dependencies...
"%VENV_PY%" -m pip install --quiet --upgrade pip
"%VENV_PY%" -m pip install --quiet -r requirements.txt
if errorlevel 1 goto :installfail

if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo   Created .env from the template. Add source credentials when you have them.
)

"%VENV_PY%" -m app.cli init
if errorlevel 1 goto :dbfail

echo.
echo   RiskDesk is starting on http://127.0.0.1:8080
echo   Press Ctrl+C to stop.
echo.
"%VENV_PY%" -m app.cli serve --host 127.0.0.1 --port 8080
goto :eof

:wrongfolder
echo.
echo   This does not look like the RiskDesk project folder.
echo   Current folder: %CD%
echo.
echo   Expected requirements.txt and app\cli.py here. Run run.bat from inside
echo   the extracted folder. If you extracted the zip by dragging it, check you
echo   are not one level too high - Windows sometimes creates riskdesk\riskdesk\.
echo.
pause
exit /b 1

:nopython
echo.
echo   RiskDesk needs Python 3.10 or newer, and could not find it.
echo   Install it from https://www.python.org/downloads/windows/
echo   and tick "Add python.exe to PATH" during setup.
echo.
pause
exit /b 1

:installfail
echo.
echo   Dependency install failed. Check your network or proxy settings.
echo.
pause
exit /b 1

:dbfail
echo.
echo   Database setup failed. See the error above.
echo.
pause
exit /b 1
