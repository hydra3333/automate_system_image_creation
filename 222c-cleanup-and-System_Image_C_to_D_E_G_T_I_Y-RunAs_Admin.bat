@echo off
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION

:: =============================================================================
:: This script performs a full system maintenance routine:
::  - Disk Cleanup using a saved profile
::  - Ensures System Protection is enabled on C:
::  - Deletes all existing restore points
::  - Creates a new restore point
::  - Creates a system image backup of C:
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

cd "%~dp0"
set "sageset_profile=1"

set "DEBUG=True"
REM set "DEBUG=False"

:: --- If we want to perform cleanups, set it here ---
set "Perform_Cleanup=True"
REM set "Perform_Cleanup=False"

:: -------------------------------------------------------------
:: --- Select the target drive(s) to backup to
REM SET "INITIAL_TARGET_DRIVE_LIST=D: E: G: T: I: Y:"
SET "INITIAL_TARGET_DRIVE_LIST=G: T:"
SET "TARGET_DRIVE_LIST="
for %%Z in (!INITIAL_TARGET_DRIVE_LIST!) do (
  rem normalize spacing
  set "TARGET_DRIVE_LIST=!TARGET_DRIVE_LIST! %%Z"
)
:: --- Uncomment ONLY ONE below to backup to just that one drive
REM SET "TARGET_DRIVE_LIST=D:"
REM SET "TARGET_DRIVE_LIST=E:"
REM SET "TARGET_DRIVE_LIST=G:"
REM SET "TARGET_DRIVE_LIST=T:"
REM SET "TARGET_DRIVE_LIST=I:"
REM SET "TARGET_DRIVE_LIST=Y:"
ECHO Targeting backup drives: %TARGET_DRIVE_LIST%
:: -------------------------------------------------------------

:: -------------------------------------------------------------
:: --- Allow for early exit if we have a drive which
:: --- does not exist or has insufficient disk space etc
for %%Z in (!TARGET_DRIVE_LIST!) do (
    set "CURRENT_TARGET_DRIVE=%%~Z"
    set "HEADROOM_PCT=30"
    REM --- Checks a target drive for issues.
    REM --- If it returns, we are OK to continue.
    call :precheck_target_drive "!CURRENT_TARGET_DRIVE!" "!HEADROOM_PCT!"
    REM --- If it returns to here, we are OK to continue.
)
:: -------------------------------------------------------------

:: -------------------------------------------------------------
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

IF /I "%Perform_Cleanup%" EQU "True" (
    echo ==============================================================
    REM --- Deletes temp files under C:\Windows\Temp
    call :cleanup_c_windows_temp
    echo ==============================================================

    echo ==============================================================
    REM --- Deletes user temp files (adjust user profile path)
    call :cleanup_c_temp_for_every_user
    echo ==============================================================

    echo ==============================================================
    REM --- Clear browser cache (Edge, Chrome, Firefox if installed)
    call :clear_browser_data_for_all_users
    echo ==============================================================

    echo ==============================================================
    REM --- Empty Recycle Bin C: only not possible directly, this empties all
    call :empty_recycle_bins
    echo ==============================================================

    echo ==============================================================
    REM --- Run Disk Cleanup using preconfigured profile, over all disk drives ---
    echo Running Disk Cleanup with profile %sageset_profile% ...
    echo cleanmgr /sagerun:%sageset_profile%
    cleanmgr /sagerun:%sageset_profile%
    echo ==============================================================
    timeout /t 2 >nul
)

:: --- List remaining restore points on C: ---
echo ==============================================================
echo Listing remaining restore points on C: ...
call :list_remaining_restore_points_on_C
echo ==============================================================
timeout /t 2 >nul

:: --- Ensure System Protection is enabled for C: ---
echo ==============================================================
echo Checking and enabling System Protection for C: ...
call :enable_System_Protection_on_C
echo ==============================================================
timeout /t 2 >nul


PAUSE
exit


:: --- Resize Shadow Storage limit to 100GB ---
echo ==============================================================
echo Resizing shadow storage limit to 100GB ...
echo powershell -ExecutionPolicy Bypass -NoProfile -Command "vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=100GB"
powershell -ExecutionPolicy Bypass -NoProfile -Command "vssadmin Resize ShadowStorage /For=C: /On=C: /MaxSize=100GB"
echo ==============================================================
timeout /t 2 >nul

REM --- Delete all existing Restore Points on C: due to a long time limitation setting for Creating a new Restore Point on C: ---
echo ==============================================================
echo Deleting all restore points on C: ...
echo powershell -ExecutionPolicy Bypass -NoProfile -Command "vssadmin delete shadows /for=C: /all /quiet"
powershell -ExecutionPolicy Bypass -NoProfile -Command "vssadmin delete shadows /for=C: /all /quiet"
echo ==============================================================
timeout /t 2 >nul

:: --- Create a new Restore Point on C: ---
echo ==============================================================
echo Creating a new Restore Point on C: ...
echo powershell -ExecutionPolicy Bypass -NoProfile -Command "Checkpoint-Computer -Description 'Scripted Restore Point' -RestorePointType 'MODIFY_SETTINGS'"
powershell -ExecutionPolicy Bypass -NoProfile -Command "Checkpoint-Computer -Description 'Scripted Restore Point' -RestorePointType 'MODIFY_SETTINGS'"
echo ==============================================================
timeout /t 2 >nul

:: --- Decide on which backups to do and do them ---
:do_backup
for %%Z in (!TARGET_DRIVE_LIST!) do (
    set "CURRENT_TARGET_DRIVE=%%~Z"
    echo **************************************************************
    echo Doing System Image Backup of C: to "!CURRENT_TARGET_DRIVE!" ...
    call :do_system_image_of_C_drive "!CURRENT_TARGET_DRIVE!"
    echo **************************************************************
    REM --- If it returns to here, we are OK to continue.
)




:: --- Disk Space Summary
echo ==============================================================
echo DISK SPACE SUMMARY
echo powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-PSDrive -PSProvider 'FileSystem' | Select Name, Used, Free, @{Name='UsedGB';Expression={[math]::Round($_.Used / 1GB, 1)}}, @{Name='FreeGB';Expression={[math]::Round($_.Free / 1GB, 1)}} | Format-Table -AutoSize"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-PSDrive -PSProvider 'FileSystem' | Select Name, Used, Free, @{Name='UsedGB';Expression={[math]::Round($_.Used / 1GB, 1)}}, @{Name='FreeGB';Expression={[math]::Round($_.Free / 1GB, 1)}} | Format-Table -AutoSize"
echo ==============================================================

PAUSE
goto :eof



REM ================================================================================================================
REM ================================================================================================================
:precheck_target_drive
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM Check for with issues with and enough free space on TARGET_DRIVE = %~1
set "TARGET_DRIVE=%~1"
set "HEADROOM_PCT=%~2"
if "%TARGET_DRIVE%"=="" set "TARGET_DRIVE=D:"
if "%HEADROOM_PCT%"=="" set "HEADROOM_PCT=30"
echo =====================================================================================================
echo Checking free space and headroom on drive %TARGET_DRIVE% with headroom %HEADROOM_PCT%%% ...
REM
call :precheck_target_drive_using_powerscript "%TARGET_DRIVE%" "%HEADROOM_PCT%"
set "RC=%ERRORLEVEL%"
REM
rem Handle errors/high codes first (cmd's IF ERRORLEVEL is >= comparison)
if %RC% GEQ 100 goto :fatal
if %RC% GEQ  92 goto :cancelled_key
if %RC% GEQ  91 goto :cancelled_flag
if %RC% GEQ  90 goto :cancelled_ctrlc
if %RC% GEQ   9 goto :format_fail
if %RC% GEQ   8 goto :wb_fail
if %RC% GEQ   7 goto :vss_fail
if %RC% GEQ   6 goto :refused
if %RC% GEQ   5 goto :not_ntfs
if %RC% GEQ   4 goto :no_space
if %RC% GEQ   3 goto :precheck
if %RC% GEQ   2 goto :bad_args
if %RC% GEQ   1 goto :generic
echo Space check drive %TARGET_DRIVE% passed.
echo =====================================================================================================
goto :eof
:no_space
echo ERROR: drive %TARGET_DRIVE% does not have enough free space (with %HEADROOM_PCT%%% headroom).
echo Review the printed drive table above and pick another target drive, or free up space.
goto :finish_error
:bad_args
echo ERROR: bad arguments to the checker for target drive %TARGET_DRIVE%
goto :finish_error
:precheck
echo ERROR: target drive %TARGET_DRIVE% not ready or not a filesystem drive.
goto :finish_error
:refused
echo ERROR: target drive %TARGET_DRIVE% is forbidden by policy.
goto :finish_error
:not_ntfs
echo ERROR: target drive %TARGET_DRIVE% is not NTFS (enforcement enabled).
goto :finish_error
:vss_fail
:wb_fail
:format_fail
:cancelled_key
:cancelled_flag
:cancelled_ctrlc
:fatal
:generic
:finish_error
echo ERROR: failed target drive %TARGET_DRIVE% pre-check (code %RC%). Exiting.
echo =====================================================================================================
EXIT %RC%
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:precheck_target_drive_using_powerscript
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
rem Usage: call :precheck_target_drive_using_powerscript "D:" "30"
rem %~1 = TargetDrive (default D:)
rem %~2 = HeadroomPercent (default 30)
set "RUNPS_ARG1=%~1"
set "RUNPS_ARG2=%~2"
REM replace unfortunately dos-generated double carats with a single carat
set "RUNPS_ARG1=%RUNPS_ARG1:^^=^%"
set "RUNPS_ARG2=%RUNPS_ARG2:^^=^%"
rem Default values if empty
if "%RUNPS_ARG1%"=="" set "RUNPS_ARG1=D:"
if "%RUNPS_ARG2%"=="" set "RUNPS_ARG2=30"
echo === precheck_target_drive - TargetDrive="%RUNPS_ARG1%" Headroom_PCT="%RUNPS_ARG2%"%% Running PowerShell via :RunPS ===
REM 
REM ===================================================================================================
REM wbadmin VERSION-ID HANDLING (READ ME)
REM 
REM • The canonical key for wbadmin operations is the literal text shown after:
REM       "Version identifier: MM/DD/YYYY-HH:MM"
REM   This represents a UTC time in US format. Pass that string verbatim to -version:.
REM 
REM • Do NOT use "Backup time:" for logic (it is local-time, locale-formatted, and DST-sensitive),
REM   and do not assume the listing order is newest→oldest.
REM 
REM • When parsing/sorting:
REM     $us   = [System.Globalization.CultureInfo]::GetCultureInfo('en-US')
REM     $ids  = (wbadmin get versions ... | Select-String '^\s*Version identifier:\s*(\d{2}/\d{2}/\d{4}-\d{2}:\d{2})\s*$' -AllMatches |
REM              ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value })
REM     $latest = $ids | Sort-Object { [datetime]::ParseExact($_,'MM/dd/yyyy-HH:mm',$us) } -Descending | Select-Object -First 1
REM     # Use $latest verbatim with -version:
REM 
REM • Folder timestamps (WindowsImageBackup\<Machine>\Backup YYYY-MM-DD HHMMSS) are typically UTC;
REM   however, the printed Version identifier remains the authoritative argument value.
REM 
REM • Always include -machine when the target contains multiple PCs, and quote all parameters.
REM • Version identifier granularity is minutes; folders include seconds.
REM ===================================================================================================
REM
call :RunPS ^
  "$TargetDrive = $env:RUNPS_ARG1" ^
  "$HeadroomPercent = $env:RUNPS_ARG2" ^
  "Write-Host ('Starting pre-checks ... Target: {0}  Headroom: {1}%%%%' -f $TargetDrive, $HeadroomPercent) -ForegroundColor Cyan" ^
  "$ErrorActionPreference = 'Stop'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "$TargetDrive = $TargetDrive.Trim()" ^
  "if ($TargetDrive -match '^[a-zA-Z]$')   { $TargetDrive += ':' }" ^
  "if ($TargetDrive -match '^[a-zA-Z]:\\?$'){ $TargetDrive = $TargetDrive.Substring(0,2) }" ^
  "$TargetDrive = $TargetDrive.ToUpper()" ^
  "if ($TargetDrive -notmatch '^[A-Z]:$') {" ^
  "    Abort ""TargetDrive '$TargetDrive' must look like 'F:' (drive letter + colon)."" $EXIT.BAD_ARGS" ^
  "}" ^
  "Check-Abort" ^
  "$dl   = $TargetDrive[0]" ^
  "$root = ""$TargetDrive\""" ^
  "try {" ^
  "    $psd = Get-PSDrive -Name $dl -PSProvider FileSystem -ErrorAction Stop" ^
  "} catch {" ^
  "    Abort ""Drive $TargetDrive not found or not a FileSystem drive."" $EXIT.PRECHECK" ^
  "}" ^
  "if (-not (Test-Path $root)) {" ^
  "    Abort ""Drive $TargetDrive is not ready/mounted."" $EXIT.PRECHECK" ^
  "}" ^
  "$ForbiddenTargets = @('C:', 'E:', 'U:')" ^
  "if ($TargetDrive -in $ForbiddenTargets) {" ^
  "    Abort (""Refusing to use {0} as a backup target (forbidden: {1})"" -f $TargetDrive, ($ForbiddenTargets -join ', ')) $EXIT.REFUSED" ^
  "}" ^
  "$vol = Get-Volume -DriveLetter $dl -ErrorAction SilentlyContinue" ^
  "if ($vol -and $vol.FileSystem -ne 'NTFS') {" ^
  "    Write-Warning ""Target $TargetDrive is $($vol.FileSystem); wbadmin works best with NTFS.""" ^
  "    Abort ""Target must be NTFS."" $EXIT.NOT_NTFS" ^
  "}" ^
  "Write-Host (""Examining backup target: {0}  (Free: {1:N1} GB)"" -f $TargetDrive, ($psd.Free/1GB))" ^
  "Check-Abort" ^
  "$usedC = (Get-PSDrive -Name C).Used" ^
  "$exclude =" ^
  "    @('C:\pagefile.sys','C:\hiberfil.sys','C:\swapfile.sys') |" ^
  "    Where-Object { Test-Path $_ } |" ^
  "    ForEach-Object { (Get-Item $_).Length } |" ^
  "    Measure-Object -Sum | Select-Object -ExpandProperty Sum" ^
  "if (-not $exclude) { $exclude = 0 }" ^
  "$criticalAllowance = 2GB" ^
  "$estimateBytes = [math]::Ceiling( (($usedC - $exclude + $criticalAllowance) * 1.10) )" ^
  "$minBytes = [math]::Ceiling( $estimateBytes * (1 + ($HeadroomPercent/100)) )" ^
  "Check-Abort" ^
  "$freeTarget = $psd.Free" ^
  "Write-Host ( ""Estimated System Image size: {0:N1} GB"" -f ($estimateBytes/1GB) )" ^
  "Write-Host ( ""Required free disk space (including {0}%%%% headroom): {1:N1} GB"" -f $HeadroomPercent, ($minBytes/1GB) )" ^
  "if ($freeTarget -lt $minBytes) {" ^
  "    Write-Host ''" ^
  "    Write-Host 'Other drives summary (headroom applied):'" ^
  "    Get-PSDrive -PSProvider FileSystem |" ^
  "      Where-Object { $_.Name -ne 'C' -and (""{0}:"" -f $_.Name) -notin $ForbiddenTargets } |" ^
  "      Select-Object @{n='Drive';e={(""{0}:"" -f $_.Name)}}," ^
  "                    @{n='FreeGB';e={[math]::Round($_.Free/1GB,1)}}," ^
  "                    @{n='Fits';e={ $_.Free -ge $minBytes }} |" ^
  "      Sort-Object Fits, FreeGB -Descending |" ^
  "      Format-Table -AutoSize" ^
  "    Abort ( ""{0} too small for a full image with headroom (need ~{1:N1} GB, have {2:N1} GB)."" -f $TargetDrive, ($minBytes/1GB), ($freeTarget/1GB) ) $EXIT.NO_SPACE" ^
  "}" ^
  "Write-Host 'Target appears large enough for this backup (including headroom).' -ForegroundColor Green" ^
  "Check-Abort" ^
  "Unregister-Event -SourceIdentifier ConsoleCancelEvent -ErrorAction SilentlyContinue | Out-Null" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:cleanup_c_windows_temp
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM no parameters for this, call :RunPS directly
call :RunPS ^
  "$ErrorActionPreference = 'Stop'" ^
  "$ProgressPreference = 'SilentlyContinue'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "Require-Admin 'Cleaning C:\Windows\TEMP folder'" ^
  "Check-Abort" ^
  "$tempPath = ""C:\Windows\TEMP""" ^
  "if (Test-Path $tempPath) {" ^
  "    try {" ^
  "        Write-Host ""Cleaning folder $tempPath ..."" -ForegroundColor White" ^
  "        # Get item count before cleanup (for reporting)" ^
  "        $itemCount = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count" ^
  "        # Get size before cleanup (for reporting)" ^
  "        $beforeSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB" ^
  "        Write-Host ""$tempPath ($('{0:N1}' -f $itemCount) items) ($('{0:N1}' -f $beforeSize) MB)"" -NoNewline" ^
  "        Remove-Item -Path ""$tempPath\*"" -Recurse -Force -ErrorAction SilentlyContinue" ^
  "        $afterSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB" ^
  "        $freed = $beforeSize - $afterSize" ^
  "        Write-Host "" folder cleaned ($('{0:N1}' -f $freed) MB freed)"" -ForegroundColor Green" ^
  "    } catch {" ^
  "        Write-Host ""WARNING ONLY: Error cleaning $tempPath : $($_.Exception.Message)"" -ForegroundColor Yellow" ^
  "    }" ^
  "} else {" ^
  "    Write-Host ""WARNING ONLY: $tempPath folder unavailable for cleaning"" -ForegroundColor Yellow" ^
  "}" ^
  "Check-Abort" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:cleanup_c_temp_for_every_user
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM no parameters for this, call :RunPS directly
call :RunPS ^
  "$ErrorActionPreference = 'Stop'" ^
  "$ProgressPreference = 'SilentlyContinue'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "Require-Admin 'Cleaning TEMP folders for every user'" ^
  "Check-Abort" ^
  "$userDirs = Get-ChildItem ""C:\Users"" -Directory | Where-Object {" ^
  "    $_.Name -notin @(""Public"", ""Default"", ""Default User"", ""All Users"") -and" ^
  "    $_.Name -notlike ""defaultuser*""" ^
  "}" ^
  "Write-Host ""Cleaning TEMP folders for $($userDirs.Count) users...""  -ForegroundColor Cyan" ^
  "foreach ($userDir in $userDirs) {" ^
  "    $userName = $userDir.Name" ^
  "    $tempPath = ""C:\Users\$userName\AppData\Local\Temp""" ^
  "    if (Test-Path $tempPath) {" ^
  "        try {" ^
  "            # Get item count and size before cleanup (for reporting)" ^
  "            $listing = Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue" ^
  "            $itemCount = $listing.Count" ^
  "            $beforeSize = ($listing | Measure-Object -Property Length -Sum).Sum / 1MB" ^
  "            Write-Host ""User: $userName Folder: $tempPath\* ($('{0:N1}' -f $itemCount) items) ($('{0:N1}' -f $beforeSize) MB) before Cleaning "" -NoNewline" ^
  "            Remove-Item ""$tempPath\*"" -Recurse -Force -ErrorAction SilentlyContinue" ^
  "            $afterSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB" ^
  "            $freed = $beforeSize - $afterSize" ^
  "            Write-Host ""      Cleaned ($('{0:N1}' -f $freed) MB freed)"" -ForegroundColor Green" ^
  "        } catch {" ^
  "            Write-Host ""WARNING ONLY: Error cleaning TEMP for $userName : $($_.Exception.Message)"" -ForegroundColor Yellow" ^
  "        }" ^
  "    } else {" ^
  "        Write-Host ""WARNING ONLY: User: $userName - No TEMP folder"" -ForegroundColor Yellow" ^
  "    }" ^
  "}" ^
  "Write-Host ""TEMP cleanup completed for all users"" -ForegroundColor Cyan" ^
  "Check-Abort" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:clear_browser_data_for_all_users
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM --- Clear browser cache (Edge, Chrome, Firefox if installed)
REM ==============================================================
REM Google Chrome
REM Microsoft Edge
REM Mozilla Firefox
REM Cleaning browser caches...
REM    Preserved (Safe)
REM       Saved passwords
REM       Cookies (i.e. logins and session tokens)
REM       Bookmarks
REM       Browser history
REM       Extensions and settings
REM Removed (Only cached temporary files — things like)
REM       Images, scripts, and style sheets stored locally to speed up browsing
REM       Disk-based "temporary blobs" and site assets
REM       These are safe to delete and do not affect functionality or user data.

REM no parameters for this, call :RunPS directly
call :RunPS ^
  "$ErrorActionPreference = 'Stop'" ^
  "$ProgressPreference = 'SilentlyContinue'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "Require-Admin 'Cleaning browser caches for all users'" ^
  "Write-Host 'Stopping running browsers to avoid file locks...'" ^
  "Get-Process chrome, msedge, msedgewebview2, firefox, opera, brave -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue" ^
  "Check-Abort" ^
  "# Get all user directories, excluding system accounts" ^
  "$userDirs = Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') -and $_.Name -notlike 'defaultuser*' }" ^
  "Write-Host (""Cleaning caches for "" + $userDirs.Count + "" user(s)..."") -ForegroundColor Cyan" ^
  "foreach($userDir in $userDirs){" ^
  "  $userName = $userDir.Name" ^
  "  Write-Host ("" Cleaning User: "" + $userName) -ForegroundColor White" ^
  "  Check-Abort" ^
  "  # ---------- Chrome ----------" ^
  "  try {" ^
  "    $chromeRoot = ""C:\Users\$userName\AppData\Local\Google\Chrome\User Data""" ^
  "    if(Test-Path $chromeRoot){" ^
  "      $profiles = Get-ChildItem $chromeRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+|Guest Profile)$' }" ^
  "      $cleaned = 0" ^
  "      foreach($p in $profiles){" ^
  "        $paths = @(" ^
  "          (Join-Path $p.FullName 'Cache\*')," ^
  "          (Join-Path $p.FullName 'Cache\Cache_Data\*')," ^
  "          (Join-Path $p.FullName 'Media Cache\*')," ^
  "          (Join-Path $p.FullName 'Code Cache\*')," ^
  "          (Join-Path $p.FullName 'GPUCache\*')," ^
  "          (Join-Path $p.FullName 'Service Worker\CacheStorage\*')," ^
  "          (Join-Path $p.FullName 'Service Worker\ScriptCache\*')" ^
  "        )" ^
  "        # removed (Join-Path $p.FullName 'Network\*'),  # as network houses cookies, deleting cookies logs you out of all browser websites" ^
  "        foreach($pp in $paths){ Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue }" ^
  "        $cleaned++" ^
  "      }" ^
  "      Write-Host ('  Chrome: cleaned ' + $cleaned + ' profile(s) for ' +  $userName) -ForegroundColor Green" ^
  "    } else {" ^
  "      Write-Host ('  Chrome: no profile root found for ' + $userName) -ForegroundColor Yellow" ^
  "    }" ^
  "  } catch {" ^
  "      Write-Host (""  Chrome: "" + $_.Exception.Message) -ForegroundColor Red" ^
  "  }" ^
  "  # ---------- Edge (Chromium) ----------" ^
  "  try {" ^
  "    $edgeRoot = ""C:\Users\$userName\AppData\Local\Microsoft\Edge\User Data""" ^
  "    if(Test-Path $edgeRoot){" ^
  "      $profiles = Get-ChildItem $edgeRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+|Guest Profile)$' }" ^
  "      $cleaned = 0" ^
  "      foreach($p in $profiles){" ^
  "        $paths = @(" ^
  "          (Join-Path $p.FullName 'Cache\*')," ^
  "          (Join-Path $p.FullName 'Cache\Cache_Data\*')," ^
  "          (Join-Path $p.FullName 'Media Cache\*')," ^
  "          (Join-Path $p.FullName 'Code Cache\*')," ^
  "          (Join-Path $p.FullName 'GPUCache\*')," ^
  "          (Join-Path $p.FullName 'Network\*')," ^
  "          (Join-Path $p.FullName 'Service Worker\CacheStorage\*')," ^
  "          (Join-Path $p.FullName 'Service Worker\ScriptCache\*')" ^
  "        )" ^
  "        foreach($pp in $paths){ Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue }" ^
  "        $cleaned++" ^
  "      }" ^
  "      Write-Host ('  Edge: cleaned ' + $cleaned + ' profile(s) for ' +  $userName) -ForegroundColor Green" ^
  "    } else {" ^
  "      Write-Host ('  Edge: no profile root found for ' + $userName) -ForegroundColor Yellow" ^
  "    }" ^
  "  } catch {" ^
  "    Write-Host (""  Edge: "" + $_.Exception.Message) -ForegroundColor Red" ^
  "  }" ^
  "  # ---------- Firefox ----------" ^
  "  try {" ^
  "    $ffLocal = ""C:\Users\$userName\AppData\Local\Mozilla\Firefox\Profiles""" ^
  "    if(Test-Path $ffLocal){" ^
  "      $profiles = Get-ChildItem $ffLocal -Directory -ErrorAction SilentlyContinue" ^
  "      $cleaned = 0" ^
  "      foreach($p in $profiles){" ^
  "        $paths = @(" ^
  "          (Join-Path $p.FullName 'cache2\*')," ^
  "          (Join-Path $p.FullName 'startupCache\*')," ^
  "          (Join-Path $p.FullName 'thumbnails\*')," ^
  "          (Join-Path $p.FullName 'shader-cache\*')," ^
  "          (Join-Path $p.FullName 'jumpListCache\*')" ^
  "        )" ^
  "        foreach($pp in $paths){ Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue }" ^
  "        $cleaned++" ^
  "      }" ^
  "      Write-Host ('  Firefox: cleaned ' + $cleaned + ' profile(s) for ' +  $userName) -ForegroundColor Green" ^
  "    } else { Write-Host '  Firefox: no profile root found' -ForegroundColor Yellow }" ^
  "  } catch {" ^
  "    Write-Host (""  Firefox: "" + $_.Exception.Message) -ForegroundColor Red" ^
  "  }" ^
  "}" ^
  "Check-Abort" ^
  "Write-Host 'Browser cache cleanup completed.' -ForegroundColor Cyan" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:empty_recycle_bins
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM --- Empty Recycle Bins
REM no parameters for this, call :RunPS directly
call :RunPS ^
  "$ErrorActionPreference = 'Stop'" ^
  "$ProgressPreference = 'SilentlyContinue'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "Require-Admin 'Emptyping Recycle Bin for C: drive'" ^
  "Check-Abort" ^
  "try {" ^
  "    Write-Host 'Emptying Recycle Bin for C: drive' -ForegroundColor White" ^
  "    Clear-RecycleBin -DriveLetter C -Force -ErrorAction Continue" ^
  "    Check-Abort" ^
  "    Write-Host 'Emptied Recycle Bin for C: successfully.' -ForegroundColor Green" ^
  "} catch {" ^
  "    Abort ""WARNING ONLY: Failed to Empty Recycle Bin for C: drive : $($_.Exception.Message)"" $EXIT.WBADMIN_FAIL" ^
  "}" ^
  "Check-Abort" ^
  "try {" ^
  "    Write-Host 'Emptying Recycle Bins on all attached drives' -ForegroundColor White" ^
  "    Clear-RecycleBin -Force -ErrorAction Continue" ^
  "    Check-Abort" ^
  "    Write-Host 'Emptied Recycle Bin for C: successfully.' -ForegroundColor Green" ^
  "} catch {" ^
  "    Abort ""WARNING ONLY: Failed to Empty Recycle Bins on all attached drives : $($_.Exception.Message)"" $EXIT.WBADMIN_FAIL" ^
  "}" ^
  "Check-Abort" ^
  "Write-Host 'Emptying Recycle Bins on all attached drives completed.' -ForegroundColor Cyan" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================

:list_remaining_restore_points_on_C
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM --- List remaining restore points on C:
REM no parameters for this, call :RunPS directly
call :RunPS ^
  "$ErrorActionPreference = 'Stop'" ^
  "$ProgressPreference = 'SilentlyContinue'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "Require-Admin 'List remaining restore points on C: drive'" ^
  "Check-Abort" ^
  "try {" ^
  "    Write-Host 'List remaining restore points on C: drive' -ForegroundColor White" ^
  "    $process = Start-Process -FilePath 'vssadmin.exe' -ArgumentList ""list"", ""shadows"", ""/for=C:"" -Wait -PassThru -NoNewWindow" ^
  "    $exitCode = $process.ExitCode" ^
  "    Check-Abort" ^
  "    if ($exitCode -ne 0) {" ^
  "        Abort ""vssadmin List remaining restore points on C: drive failed with exit code: $exitCode"" $EXIT.WBADMIN_FAIL" ^
  "    }" ^
  "    Check-Abort" ^
  "    Write-Host 'Listed remaining restore points on C: drive successfully.' -ForegroundColor Green" ^
  "} catch {" ^
  "    Abort ""WARNING ONLY: Failed to List remaining restore points on C: drive : $($_.Exception.Message)"" $EXIT.WBADMIN_FAIL" ^
  "}" ^
  "Check-Abort" ^
  "#Write-Host 'List remaining restore points on C: drive completed.' -ForegroundColor Cyan" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:enable_System_Protection_on_C
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM --- Enable System Protection on C:
REM no parameters for this, call :RunPS directly
call :RunPS_debug ^
  "$ErrorActionPreference = 'Stop'" ^
  "$ProgressPreference = 'SilentlyContinue'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "Require-Admin 'Enable System Protection on C: drive'" ^
  "Check-Abort" ^
  "try {" ^
  "  Write-Host 'Enabling System Protection on C: drive (if disabled)...' -ForegroundColor White" ^
  "  $needEnable = $false" ^
  "  # Registry hint (present even when SR is disabled)" ^
  "  $srKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue" ^
  "  if ($srKey -and ($srKey.DisableSR -eq 1)) { $needEnable = $true }" ^
  "  # CIM fallback (may be null if never enabled)" ^
  "  if (-not $needEnable) {" ^
  "    $cfg = Get-CimInstance -Namespace 'root/default' -ClassName SystemRestoreConfig -ErrorAction SilentlyContinue | Where-Object { $_.Drive -eq 'C:' }" ^
  "    if (-not $cfg -or $cfg.RPSessionInterval -lt 0) { $needEnable = $true }" ^
  "  }" ^
  "  if ($needEnable) {" ^
  "    Enable-ComputerRestore -Drive 'C:' -ErrorAction Stop" ^
  "    Start-Sleep -Seconds 3" ^
  "    Write-Host 'System Protection enabled on C: drive.' -ForegroundColor Green" ^
  "  } else {" ^
  "    Write-Host 'System Protection already enabled on C: drive.' -ForegroundColor Green" ^
  "  }" ^
  "} catch {" ^
  "  Abort ""Failed to enable System Protection on C: drive : $($_.Exception.Message)"" $EXIT.GENERIC" ^
  "}" ^
  "Check-Abort" ^
  "Write-Host 'Enable System Protection on C: drive completed.' -ForegroundColor Cyan" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:do_system_image_of_C_drive
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
REM --- Checks target drive for issues. If it returns, we are OK to continue.
set "TARGET_DRIVE=%~1"
if "%TARGET_DRIVE%"=="" set "TARGET_DRIVE=D:"
REM set "HEADROOM_PCT=30"
REM call :precheck_target_drive "%TARGET_DRIVE%" "%HEADROOM_PCT%"
echo ==============================================================
echo Creating a System Image Backup of C: onto %TARGET_DRIVE% ...
REM echo powershell -ExecutionPolicy Bypass -NoProfile -Command "wbadmin start backup -backupTarget:%TARGET_DRIVE% -include:C: -allCritical -quiet"
REM powershell -ExecutionPolicy Bypass -NoProfile -Command "wbadmin start backup -backupTarget:%TARGET_DRIVE% -include:C: -allCritical -quiet"
call :do_system_image_of_C_drive_using_powerscript "%TARGET_DRIVE%"
set "RC=%ERRORLEVEL%"
if "%RC%" NEQ "0" (
  echo ERROR: System Image Backup to %TARGET_DRIVE% failed code %RC%
  exit %RC%
)
echo System Image backup to %TARGET_DRIVE% completed successfully.
REM echo ==============================================================
REM echo List System Image Backup versions on "%~1" for "%COMPUTERNAME%"
REM echo wbadmin get versions -backuptarget:"%~1" -machine:"%COMPUTERNAME%"
REM wbadmin get versions -backuptarget:"%~1" -machine:"%COMPUTERNAME%"
REM echo ==============================================================
REM call :show_latest_system_backup_version_for_current_machine_on_target "%~1"
REM goto :eof

:do_system_image_of_C_drive_using_powerscript
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
rem Usage: call :do_system_image_of_C_drive_using_powerscript "D:"
rem %~1 = TargetDrive (default D:)
set "RUNPS_ARG1=%~1"
REM replace unfortunately dos-generated double carats with a single carat
set "RUNPS_ARG1=%RUNPS_ARG1:^^=^%"
rem Default values if empty
if "%RUNPS_ARG1%"=="" set "RUNPS_ARG1=D:"
call :RunPS ^
  "$TargetDrive = $env:RUNPS_ARG1" ^
  "$ErrorActionPreference = 'Stop'" ^
  "$EXIT = @{" ^
  "  OK=0; GENERIC=1; BAD_ARGS=2; PRECHECK=3; NO_SPACE=4; NOT_NTFS=5; REFUSED=6;" ^
  "  VSS_FAIL=7; WBADMIN_FAIL=8; FORMAT_FAIL=9;" ^
  "  CANCEL_CTRL_C=90; CANCEL_FLAG=91; CANCEL_KEY=92; UNKNOWN=99" ^
  "}" ^
  "function Abort([string]$msg, [int]$code = $EXIT.GENERIC) {" ^
  "    if ($msg) { Write-Error $msg }" ^
  "    exit $code" ^
  "}" ^
  "$script:UserCancelled = $false" ^
  "Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {" ^
  "    $script:UserCancelled = $true" ^
  "    $eventArgs.Cancel = $true" ^
  "    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'" ^
  "} | Out-Null" ^
  "function Check-Abort {" ^
  "    if ($script:UserCancelled) { Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C }" ^
  "    try {" ^
  "        if ([Console]::KeyAvailable) {" ^
  "            $k = [Console]::ReadKey($true)" ^
  "            if ($k.Key -eq 'Q') { Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY }" ^
  "        }" ^
  "    } catch { <# non-interactive host - ignore #> }" ^
  "}" ^
  "function Require-Admin([string]$Why = 'This step') {" ^
  "    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(" ^
  "                    [Security.Principal.WindowsIdentity]::GetCurrent()" ^
  "                )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" ^
  "    if (-not $isAdmin) {" ^
  "        Abort ""$Why requires Administrator. Re-run elevated."" $EXIT.PRECHECK" ^
  "    }" ^
  "}" ^
  "# ****************************** CODE ******************************" ^
  "Require-Admin 'wbadmin backup operation'" ^
  "Check-Abort" ^
  "Write-Host ""Starting System Image Backup to $TargetDrive..."" -ForegroundColor Yellow" ^
  "try {" ^
  "    #$process = Start-Process -FilePath 'wbadmin.exe' -ArgumentList ""start"", ""backup"", ""-backupTarget:$TargetDrive"", ""-include:C:"", ""-allCritical"", ""-quiet"" -Wait -PassThru -NoNewWindow" ^
  "    $process = Start-Process -FilePath 'wbadmin.exe' -ArgumentList ""start"", ""backup"", ""-backupTarget:$TargetDrive"", ""-include:C:"", ""-allCritical"" -Wait -PassThru -NoNewWindow" ^
  "    $exitCode = $process.ExitCode" ^
  "    Check-Abort" ^
  "    if ($exitCode -ne 0) {" ^
  "        Abort ""wbadmin System Image Backup failed with exit code: $exitCode"" $EXIT.WBADMIN_FAIL" ^
  "    }" ^
  "    Write-Host ""System Image Backup completed successfully."" -ForegroundColor Green" ^
  "} catch {" ^
  "    Abort ""ERROR: Failed to execute wbadmin System Image Backup : $($_.Exception.Message)"" $EXIT.WBADMIN_FAIL" ^
  "}" ^
  "Check-Abort" ^
  "exit $EXIT.OK"
set "RC=%ERRORLEVEL%"
exit /b %RC%
REM  "try {" ^
REM  "     wbadmin start backup -backupTarget:$TargetDrive -include:C: -allCritical -quiet" ^
REM  "     Check-Abort" ^
REM  "} catch {" ^
REM  "    Abort ""ERROR CREATING SYSTEM IMAGE BACKUP TO DRIVE $TargetDrive."" $EXIT.WBADMIN_FAIL" ^
REM  "}" ^
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:: ------------------------------------------------------------
:: :get_latest_system_backup_version_on_target_for_machine <BACKUP_TARGET> <MACHINE>
::   Sets LATEST_VERSION to newest Version identifier for MACHINE.
::   Returns ERRORLEVEL 0 if found, 1 if none.
:: ONLY WORKS WHEN RUN AS ADMIN
:: ------------------------------------------------------------
REM ==============================================================================================
REM wbadmin VERSION-ID HANDLING (READ ME)
REM ----------------------------------------------------------------------------------------------
REM • The only reliable key for wbadmin restore/inspection is the text after:
REM       "Version identifier: MM/DD/YYYY-HH:MM"
REM   This is a UTC timestamp rendered in US format. Pass it *verbatim* to:
REM       wbadmin get items -version:"MM/DD/YYYY-HH:MM" -backuptarget:"X:" -machine:"PCNAME"
REM
REM • DO NOT parse or depend on the "Backup time:" line — it is shown in local time/format and
REM   can differ by locale/DST. Also avoid relying on console ordering of versions.
REM
REM • When extracting/version-sorting in scripts:
REM     - Capture only the Version identifier token via regex.
REM     - Sort using an en-US ParseExact("MM/dd/yyyy-HH:mm") model, then use the newest token.
REM     - Always quote: -version:"..." -backuptarget:"..." -machine:"..."
REM
REM • Folder names under WindowsImageBackup\<Machine>\Backup YYYY-MM-DD HHMMSS may be UTC too,
REM   but we still consider the printed Version identifier string authoritative for wbadmin args.
REM
REM • Multiple machines on one target: always include -machine:"PCNAME".
REM
REM • Resolution: Version identifier is minute-precision; folder names include seconds.
REM ==============================================================================================
:get_latest_system_backup_version_on_target_for_machine
setlocal
set "BACKUP_TARGET=%~1"
set "MACHINE=%~2"
for /f "usebackq delims=" %%V in (`
  powershell -NoProfile -Command "$bt='%BACKUP_TARGET%'; $mc='%MACHINE%'; $us=[Globalization.CultureInfo]::GetCultureInfo('en-US'); $args=@('-backuptarget:{0}' -f $bt); if($mc){ $args+=('-machine:{0}' -f $mc) }; $text = (wbadmin get versions @args) | Out-String; $ids = $text -split \"`r?`n\" | Select-String '^\s*Version identifier:\s*(\d{2}/\d{2}/\d{4}-\d{2}:\d{2})\s*$' -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value }; if(-not $ids -or $ids.Count -eq 0){ [Environment]::Exit(1) }; $latest = $ids | Sort-Object { [datetime]::ParseExact($_,'MM/dd/yyyy-HH:mm',$us) } -Descending | Select-Object -First 1; Write-Output $latest"
`) do (
  endlocal & set "LATEST_VERSION=%%V" & exit /b 0
)
endlocal & exit /b 1
goto :eof
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:: ------------------------------------------------------------
:: :show_latest_system_backup_version_for_current_machine_on_target on <BACKUP_TARGET> and show latest
:: Shows the latest system image backup on <BACKUP_TARGET> for the current machine
:: ONLY WORKS WHEN RUN AS ADMIN
:: ----------------------------------------------------------
REM ==============================================================================================
REM wbadmin VERSION-ID HANDLING (READ ME)
REM ----------------------------------------------------------------------------------------------
REM • The only reliable key for wbadmin restore/inspection is the text after:
REM       "Version identifier: MM/DD/YYYY-HH:MM"
REM   This is a UTC timestamp rendered in US format. Pass it *verbatim* to:
REM       wbadmin get items -version:"MM/DD/YYYY-HH:MM" -backuptarget:"X:" -machine:"PCNAME"
REM
REM • DO NOT parse or depend on the "Backup time:" line — it is shown in local time/format and
REM   can differ by locale/DST. Also avoid relying on console ordering of versions.
REM
REM • When extracting/version-sorting in scripts:
REM     - Capture only the Version identifier token via regex.
REM     - Sort using an en-US ParseExact("MM/dd/yyyy-HH:mm") model, then use the newest token.
REM     - Always quote: -version:"..." -backuptarget:"..." -machine:"..."
REM
REM • Folder names under WindowsImageBackup\<Machine>\Backup YYYY-MM-DD HHMMSS may be UTC too,
REM   but we still consider the printed Version identifier string authoritative for wbadmin args.
REM
REM • Multiple machines on one target: always include -machine:"PCNAME".
REM
REM • Resolution: Version identifier is minute-precision; folder names include seconds.
REM ==============================================================================================
:show_latest_system_backup_version_for_current_machine_on_target
setlocal
set "BACKUP_TARGET=%~1"
call :get_latest_system_backup_version_on_target_for_machine "%BACKUP_TARGET%" "%COMPUTERNAME%"
if errorlevel 1 (echo No System Image Backups for machine "%COMPUTERNAME%" on drive "%BACKUP_TARGET%" & goto :eof)
echo ==============================================================
echo Latest System Image Backup on drive "%BACKUP_TARGET%" for machine "%COMPUTERNAME%" is version "%LATEST_VERSION%"
echo wbadmin get items -version:"%LATEST_VERSION%" -backuptarget:"%BACKUP_TARGET%" -machine:"%COMPUTERNAME%"
wbadmin get items -version:"%LATEST_VERSION%" -backuptarget:"%BACKUP_TARGET%" -machine:"%COMPUTERNAME%"
echo ==============================================================
endlocal
goto :eof
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:: ------------------------------------------------------------
:: :get_system_backup_machines_on_target on <BACKUP_TARGET>
::   Sets MACHINES to space-separated list of machine names
::   (based on subfolders under \WindowsImageBackup).
::   Returns ERRORLEVEL 0 if any found, 1 if none.
:: ONLY WORKS WHEN RUN AS ADMIN
:: ------------------------------------------------------------
REM ==============================================================================================
REM wbadmin VERSION-ID HANDLING (READ ME)
REM ----------------------------------------------------------------------------------------------
REM • The only reliable key for wbadmin restore/inspection is the text after:
REM       "Version identifier: MM/DD/YYYY-HH:MM"
REM   This is a UTC timestamp rendered in US format. Pass it *verbatim* to:
REM       wbadmin get items -version:"MM/DD/YYYY-HH:MM" -backuptarget:"X:" -machine:"PCNAME"
REM
REM • DO NOT parse or depend on the "Backup time:" line — it is shown in local time/format and
REM   can differ by locale/DST. Also avoid relying on console ordering of versions.
REM
REM • When extracting/version-sorting in scripts:
REM     - Capture only the Version identifier token via regex.
REM     - Sort using an en-US ParseExact("MM/dd/yyyy-HH:mm") model, then use the newest token.
REM     - Always quote: -version:"..." -backuptarget:"..." -machine:"..."
REM
REM • Folder names under WindowsImageBackup\<Machine>\Backup YYYY-MM-DD HHMMSS may be UTC too,
REM   but we still consider the printed Version identifier string authoritative for wbadmin args.
REM
REM • Multiple machines on one target: always include -machine:"PCNAME".
REM
REM • Resolution: Version identifier is minute-precision; folder names include seconds.
REM ==============================================================================================
:get_system_backup_machines_on_target
@setlocal ENABLEEXTENSIONS
@setlocal ENABLEDELAYEDEXPANSION
set "BACKUP_TARGET=%~1"
set "ROOT=%BACKUP_TARGET%\WindowsImageBackup"
set "Mlist="
set "MACHINES="
if not exist "%ROOT%\" ( endlocal & exit /b 1 )
for /f "delims=" %%D in ('dir /b /ad "%ROOT%" 2^>nul') do (
  if exist "%ROOT%\%%D\Catalog\" (
    set "Mlist=!Mlist! %%D"
  ) else if exist "%ROOT%\%%D\Backup *" (
    set "Mlist=!Mlist! %%D"
  )
)
for %%Z in (!Mlist!) do (
  rem normalize spacing
  set "MACHINES=!MACHINES! %%Z"
)
if not defined MACHINES ( endlocal & exit /b 1 )
endlocal & set "MACHINES=%MACHINES:~1%" & exit /b 0
goto :eof
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:: ------------------------------------------------------------
:: :Enumerate_system_backup_machines_on_target_show_latest_versions on <BACKUP_TARGET> and show each latest
::   Sets MACHINES to space-separated list of machine names
::   (based on subfolders under \WindowsImageBackup).
::   Returns ERRORLEVEL 0 if any found, 1 if none.
:: ONLY WORKS WHEN RUN AS ADMIN
:: ------------------------------------------------------------
REM ==============================================================================================
REM wbadmin VERSION-ID HANDLING (READ ME)
REM ----------------------------------------------------------------------------------------------
REM • The only reliable key for wbadmin restore/inspection is the text after:
REM       "Version identifier: MM/DD/YYYY-HH:MM"
REM   This is a UTC timestamp rendered in US format. Pass it *verbatim* to:
REM       wbadmin get items -version:"MM/DD/YYYY-HH:MM" -backuptarget:"X:" -machine:"PCNAME"
REM
REM • DO NOT parse or depend on the "Backup time:" line — it is shown in local time/format and
REM   can differ by locale/DST. Also avoid relying on console ordering of versions.
REM
REM • When extracting/version-sorting in scripts:
REM     - Capture only the Version identifier token via regex.
REM     - Sort using an en-US ParseExact("MM/dd/yyyy-HH:mm") model, then use the newest token.
REM     - Always quote: -version:"..." -backuptarget:"..." -machine:"..."
REM
REM • Folder names under WindowsImageBackup\<Machine>\Backup YYYY-MM-DD HHMMSS may be UTC too,
REM   but we still consider the printed Version identifier string authoritative for wbadmin args.
REM
REM • Multiple machines on one target: always include -machine:"PCNAME".
REM
REM • Resolution: Version identifier is minute-precision; folder names include seconds.
REM ==============================================================================================
:Enumerate_system_backup_machines_on_target_show_latest_versions
setlocal EnableDelayedExpansion
set "BACKUP_TARGET=%~1"
call :get_system_backup_machines_on_target "%BACKUP_TARGET%"
if errorlevel 1 (echo No machines found on %BACKUP_TARGET%. & goto :eof)
echo ==============================================================
for %%M in (%MACHINES%) do (
  call :get_latest_system_backup_version_on_target_for_machine "%BACKUP_TARGET%" "%%~M"
  if errorlevel 1 (
    echo %%M: no versions found
  ) else (
    echo **************************************************************
    echo Latest System Image Backup on drive "%BACKUP_TARGET%" for machine "%%M" is version "!LATEST_VERSION!"
    echo wbadmin get items -version:"!LATEST_VERSION!" -backuptarget:"%BACKUP_TARGET%" -machine:"%%~M"
    wbadmin get items -version:"!LATEST_VERSION!" -backuptarget:"%BACKUP_TARGET%" -machine:"%%~M"
    echo **************************************************************
  )
)
echo ==============================================================
endlocal
goto :eof
REM ================================================================================================================
REM ================================================================================================================

REM ================================================================================================================
REM ================================================================================================================
:: -------------------------------------------------------------------------------
:: :RunPS — write a temp .ps1 from given lines, then run it (auto-escapes special things for CMD)
:: Usage:  call :RunPS "line 1" "line 2" "line 3" ...
:: Notes:
::   • Each argument becomes one line in the .ps1
::   • Use %%%% to emit a single % in ps code lines (same rule for parameters)
::   • Double "" to embed a literal " inside an argument
::   • Safe inside IF/FOR blocks (uses echo()
::   • 'echo(' prints whatever follows, without confusing the block parser.
::   • Also do setlocal DisableDelayedExpansion, so ! characters won’t get eaten.
::   Returns a code to the caller (via ERRORLEVEL)
::
:: Example of Usage:
::  REM 1. ----- THE ORIGINAL IF, CALL THE FUNCTION TO DO THE POWERSHELL WITH PARAMETERS
::  IF 1 == 1 (
::      call :some_function_using_a_powershell_script "P1" "P2" ""P3"   # insteal of trying to use powershell in an IF
::  )
::  etc
::
::  REM 2. ----- THE FUNCTION TO CREATE THE POWERSHELL WITH THE PARAMETERS PASSED, AND CALL :RunPS TO RUN IT
::  :some_function_using_a_powershell_script
::  echo === a_specific_function_not_in_an_IF - Running PowerShell via :RunPS ... not inside IF ===
::  rem expose args for PowerShell to read safely (order preserved)
::  rem this has to be explicit, so we have the right number of parameters in the right order
::  set "RUNPS_ARG1=%~1"
::  set "RUNPS_ARG2=%~2"
::  set "RUNPS_ARG3=%~3"
::  REM replace unfortunately dos-generated double carats with a single carat
::  set "RUNPS_ARG1=%RUNPS_ARG1:^^=^%"
::  set "RUNPS_ARG2=%RUNPS_ARG2:^^=^%"
::  set "RUNPS_ARG3=%RUNPS_ARG3:^^=^%"
::  call :RunPS ^
::      "Write-Host ('hello from PowerShell (in a label, not in IF)')" ^
::      "Write-Host ('Parameter1=<' + $env:RUNPS_ARG1 + '>')" ^
::      "Write-Host ('Parameter2=<' + $env:RUNPS_ARG2 + '>')" ^
::      "Write-Host ('Parameter3=<' + $env:RUNPS_ARG3 + '>')" ^
::      "Write-Host ('parens () ampersand & pipe | lt < gt > caret ^ are okay')" ^
::      "Write-Host ('percent ' + [char]37 + ' okay')" ^
::      "Write-Host ('percent %%%% okay instead of [char]37')" ^
::      "Write-Host ('double-quotes ""ok""')" ^
::      "Write-Host ('single-quotes ''ok''')" ^
::      "Write-Host ('carat ^ ok')" ^
::      "$envTEMP = $env:TEMP" ^
::      "Write-Host ('TEMP=<' + $envTEMP + '>')"
:: echo === Done ===
:: -------------------------------------------------------------------------------
:RunPS
setlocal DisableDelayedExpansion
set "TMPPS=%TEMP%\runps_%RANDOM%%RANDOM%.ps1"
break > "%TMPPS%" 2>nul
:__rp_loop
if "%~1"=="" goto __rp_go
rem -- Copy arg to a work var, then escape CMD metachars so echo( won't choke.
set "L=%~1"
set "L=%L:""="%"
rem -- Escape only the CMD metachars that break echo( in a block:
set "L=%L:|=^|%"
set "L=%L:&=^&%"
set "L=%L:<=^<%"
set "L=%L:>=^>%"
REM no please do NOT do this : set "L=%L:^^=^%"
>>"%TMPPS%" echo(%L%
shift
goto __rp_loop
:__rp_go
REM echo ---------------------------------------------------------
REM type "%TMPPS%"
REM echo ---------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%TMPPS%"
set "RC=%ERRORLEVEL%"
del "%TMPPS%" >nul 2>&1
endlocal & exit /b %RC%

REM second copy is for debug
:RunPS_debug
setlocal DisableDelayedExpansion
set "TMPPS=%TEMP%\runps_%RANDOM%%RANDOM%.ps1"
break > "%TMPPS%" 2>nul
:__rp_loop_debug
if "%~1"=="" goto __rp_go_debug
rem -- Copy arg to a work var, then escape CMD metachars so echo( won't choke.
set "L=%~1"
set "L=%L:""="%"
rem -- Escape only the CMD metachars that break echo( in a block:
set "L=%L:|=^|%"
set "L=%L:&=^&%"
set "L=%L:<=^<%"
set "L=%L:>=^>%"
REM no please do NOT do this : set "L=%L:^^=^%"
>>"%TMPPS%" echo(%L%
shift
goto __rp_loop_debug
:__rp_go_debug
echo ---------------------------------------------------------
type "%TMPPS%"
echo ---------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%TMPPS%"
set "RC=%ERRORLEVEL%"
del "%TMPPS%" >nul 2>&1
endlocal & exit /b %RC%
REM ================================================================================================================
REM ================================================================================================================
