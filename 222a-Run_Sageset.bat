@echo on
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION

:: Create the sageset profile if it does not already exist
set "sageset_profile=1"

:: Check for elevation, run via PowerShell if not
REM net session >nul 2>&1
REM if %errorlevel% neq 0 (
REM     echo Requesting administrator access...
REM     powershell -ExecutionPolicy Bypass -NoProfile -Command "Start-Process cmd -ArgumentList '/c cleanmgr /sageset:%sageset_profile%' -Verb runAs"
REM ) else (
REM     cleanmgr /sageset:%sageset_profile%
REM )

cleanmgr /sageset:%sageset_profile%

pause
goto :eof
