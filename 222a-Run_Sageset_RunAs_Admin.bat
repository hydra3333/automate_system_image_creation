@echo on
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION

:: Create the sageset profile if it does not already exist
set "sageset_profile=1"

:: Check for elevation, run via PowerShell if not
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator access...
    powershell -ExecutionPolicy Bypass -NoProfile -Command "Start-Process cmd -ArgumentList '/c cleanmgr /sageset:%sageset_profile%' -Verb runAs"
) else (
    cleanmgr /sageset:%sageset_profile%
)

pause
goto :eof
