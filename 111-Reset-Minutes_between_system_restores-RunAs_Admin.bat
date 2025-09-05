@echo off
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
rem --------------------------------------------------------------------------------------------------------------------------------
rem Reset or Set System Restore Point Creation Frequency
rem HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore - SystemRestorePointCreationFrequency
rem --------------------------------------------------------------------------------------------------------------------------------
rem Run this script as Administrator
rem Microsoft Default ^(when value missing^) = 1440 minutes ^(24 hours^)
rem --------------------------------------------------------------------------------------------------------------------------------

rem Check for this being run with admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script must be run as Administrator.  Right-click on it and choose 'Run As Administrator'
    pause
    exit /b 1
)

set "keyname=HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore"
set "valuename=SystemRestorePointCreationFrequency"

echo.
echo --- BEFORE ---
echo reg query "%keyname%" /v "%valuename%" 2>nul
reg query "%keyname%" /v "%valuename%" 2>nul
if errorlevel 1 (
    echo "%valuename%" not found. Windows will be using the default ^(1440 minutes^).
)

echo.
echo Resetting System Restore Point Creation Frequency to default ^(1440 minutes^)...
echo.
echo reg delete "%keyname%" /v "%valuename%" /f
reg delete "%keyname%" /v "%valuename%" /f
if "%ERRORLEVEL%"=="0" (
    echo Successfully removed "%keyname%" - "%valuename%" from the Windows Registry
    echo Windows will now fall back to using the default ^(1440 minutes^).
) else (
    echo Windows regsitry value "%keyname%" - "%valuename%" not found or could not be removed. It may already be at default.
)

echo.
echo --- AFTER ---
echo reg query "%keyname%" /v "%valuename%" 2>nul
reg query "%keyname%" /v "%valuename%" 2>nul
if errorlevel 1 (
    echo "%valuename%" not found. Windows will be using the default ^(1440 minutes^).
)
echo.

REM echo To set a specific value for "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore - SystemRestorePointCreationFrequency" in the Windows Registry, uncomment the lines below ---
REM ... with /f ^(force^) - it will silently overwrite any existing value.
rem SET "VALUE_IN_MINUTES=720"
rem reg add "%keyname%"  /v "%valuename%" /t REG_DWORD /d %VALUE_IN_MINUTES% /f
rem Example: Restore to 1440 explicitly ^(same as default^)
rem reg add "%keyname%"  /v "%valuename%" /t REG_DWORD /d 1440 /f

pause
goto :eof
