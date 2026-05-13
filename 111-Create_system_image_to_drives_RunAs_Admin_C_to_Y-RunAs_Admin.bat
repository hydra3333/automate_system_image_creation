@echo off
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION

:: Requires: Run as Administrator
:: =============================================================================
:: Notes:
::  1. Placement :: in an IF () block breaks the IF block without fail.
::  2. Using powershell with cmd is "problematic", strings break with an IF () block
::  3. So instead call a :some_function to do the powershell using a new technique,
::     which in turn calls the common function  :RunPS to tun the powershell.
::     Be careful to set and use RUNPS_ARG* eg set "RUNPS_ARG1=%~1" in the called function
::     If wanting a % in the powershell script, use 4 of them %%%% which gets mangled down to 1 (same rule for parameters)
::     If wanting a single " in the powershell script, use  "" which gets mangled down to 1 same rule for parameters)
:: =============================================================================

rem Check for this being run with admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo This script must be run as Administrator.  Right-click on it and choose 'Run As Administrator'
    pause
    exit /b 1
)

REM ******************************************************************************
REM Set this process priority to AboveNormal using the common priority_lib.bat
REM set "priority_lib=%~dp0priority_lib.bat"
set "priority_lib=C:\000-Essential-tasks\priority_lib.bat"
echo Process priority before setting: 
call "!priority_lib!" :show_priority_of_local_process
call "!priority_lib!" :ensure_minimum_priority_of_local_process AboveNormal
echo Process priority after setting: 
call "!priority_lib!" :show_priority_of_local_process
REM ******************************************************************************

REM ******************************************************************************
REM Prevent process from sleeping using the common StayAwake_lib.bat
set "StayAwake_lib=C:\000-Essential-tasks\StayAwake_lib.bat"
call "!StayAwake_lib!" :start_StayAwake
REM ******************************************************************************

cd "%~dp0"
set "sageset_profile=1"

:: --- If we want to run in Verbose mode, set it here ---
REM set "Verbose=-Verbose"
set "Verbose="

:: --- If we want to perform cleanups, set it here ---
set "CleanupBeforehand=-CleanupBeforehand"
REM set "CleanupBeforehand=-NoCleanupBeforehand"

:: --- If we want to Purge Restore Points, set it here ---
set "PurgeRestorePoints=-PurgeRestorePoints"
REM set "PurgeRestorePoints=-NoPurgeRestorePoints"

:: --- If we want to set additional disk headroom for the system image target, set it here ---
REM set "Headroom_PCT=-Headroom_PCT 35"
set "Headroom_PCT=-Headroom_PCT 40"

set "ps1_path=%~dp0111-Create_system_image_to_drives_RunAs_Admin.ps1"

REM ----------------------------------------------------------------------------------
REM ----------------------------------------------------------------------------------

REM SET "TARGET_DRIVE_LIST=D: E: G: T: I: Y:"
REM SET "TARGET_DRIVE_LIST=D:"
REM SET "TARGET_DRIVE_LIST=E:"
REM SET "TARGET_DRIVE_LIST=G:"
REM SET "TARGET_DRIVE_LIST=T:"
REM SET "TARGET_DRIVE_LIST=I:"
SET "TARGET_DRIVE_LIST=Y:"

REM ----------------------------------------------------------------------------------
REM ----------------------------------------------------------------------------------

echo powershell -NoProfile -ExecutionPolicy Bypass -File "%ps1_path%" -Target_Drives_List "%TARGET_DRIVE_LIST%" %Headroom_PCT% %CleanupBeforehand% %PurgeRestorePoints% %Verbose%
powershell -NoProfile -ExecutionPolicy Bypass -File "%ps1_path%" -Target_Drives_List "%TARGET_DRIVE_LIST%" %Headroom_PCT% %CleanupBeforehand% %PurgeRestorePoints% %Verbose%

REM ******************************************************************************
REM Allow process from sleeping using the common StayAwake_lib.bat
call "!StayAwake_lib!" :kill_StayAwake
REM ******************************************************************************

pause
exit