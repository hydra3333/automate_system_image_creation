@echo on
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION

:: --- Check for Administrator rights ---
net session >nul 2>&1
set "EL=%errorlevel%"
if %EL% neq 0 (
    echo This script must be run as Administrator.
    pause
    exit /b
) ELSE (
    echo This script is running as Administrator. Great!
)

powershell -NoProfile -ExecutionPolicy Bypass -File "C:\000-Essential-tasks\zzz-backups_05.ps1" -Target_Drives_List "D: E: F: G: T: I: Y:" -Headroom_PCT 35 -Verbose
REM powershell -NoProfile -ExecutionPolicy Bypass -File "C:\000-Essential-tasks\zzz-backups_05.ps1" -Target_Drives_List "D: E: F: G: T: I: Y:" -Headroom_PCT 35

pause
goto :eof

