@echo off
REM ===============================================================
REM PRIORITY MANAGEMENT LIBRARY FOR BATCH SCRIPTS
REM ---------------------------------------------------------------
REM Usage:
REM   CALL priority_lib.bat :label param1 param2 ...
REM 
REM Notes:
REM   - DO NOT USE SETLOCAL in this library; variables persist in the caller
REM   - All routines accept variable names to set values in the calling script
REM   - Retains -Sta for PowerShell for future COM or STA-requiring calls
REM   - Recommended priority levels:
REM       Idle, BelowNormal, Normal, AboveNormal, High, RealTime
REM   - AboveNormal preferred over High for system stability
REM         High can starve system/background services (disk, network, UI)
REM         AboveNormal usually gives approx 95 percent of the benefit with fewer side effects
REM
REM | Name (PowerShell) | START flag     | Notes                     |
REM | ----------------- | -------------- | ------------------------- |
REM | `Idle`            | `/LOW`         | Lowest priority           |
REM | `BelowNormal`     | `/BELOWNORMAL` | Slightly deprioritized    |
REM | `Normal`          | `/NORMAL`      | Default                   |
REM | `AboveNormal`     | `/ABOVENORMAL` | Mild boost                |
REM | `High`            | `/HIGH`        | Aggressive CPU preference |
REM | `RealTime`        | `/REALTIME`    | Dangerous                 |
REM ===============================================================

REM ==========================================================================================================
REM echo [DEBUG Entered priority_lib.bat] with p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
if "%~1" equ "" goto :eof
set "priority_lib_tmp_file_path=%~dpnx0"
set "_GOTO_LABEL=%~1"
REM echo [DEBUG] target goto normal  _GOTO_LABEL = '%_GOTO_LABEL%'
REM echo [DEBUG] target goto delayed _GOTO_LABEL = '!_GOTO_LABEL!'
shift
REM echo [DEBUG] goto !_GOTO_LABEL! with p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
goto %_GOTO_LABEL%
goto :eof
REM ==========================================================================================================

REM ------------------------------------------------------------------
:get_PID_of_local_process
REM p1 = variable name to set in calling script (e.g., CMDPID)
REM Returns the parent PID of this CMD process
REM Example: call priority_lib.bat :get_PID_of_local_process CMDPID
REM the parent of the spawned powershell process is this process
REM echo [DEBUG ENTERED :get_PID_of_local_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
REM echo [DEBUG] powershell processes:
REM powershell -NoLogo -ExecutionPolicy Bypass -Sta -NonInteractive -command "(Get-CimInstance Win32_Process)"
ECHO *** entered '%priority_lib_tmp_file_path%' :get_PID_of_local_process
set "PRIORITY_LIB_TMP_VALUE_FILE_PID=%TEMP%\priority_lib_tmp_value_file_pid.tmp"
set "TMP_VAL="
del /f "!PRIORITY_LIB_TMP_VALUE_FILE_PID!" >nul 2>&1
powershell -NoLogo -ExecutionPolicy Bypass -Sta -NonInteractive -command "(Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID)).ParentProcessId" > "!PRIORITY_LIB_TMP_VALUE_FILE_PID!"
set /p TMP_VAL=<"!PRIORITY_LIB_TMP_VALUE_FILE_PID!"
del /f "!PRIORITY_LIB_TMP_VALUE_FILE_PID!" >nul 2>&1
set "%~1=!TMP_VAL!"
REM echo [DEBUG] :get_PID_of_local_process Process Id=!TMP_VAL!
ECHO *** exiting '%priority_lib_tmp_file_path%' :get_PID_of_local_process
goto :eof

REM ------------------------------------------------------------------
:get_priority_of_specific_process
REM p1 = PID to query
REM p2 = variable name to set in calling script (e.g., PROC_PRIO)
REM Example: call priority_lib.bat :get_priority_of_specific_process 1234 PROC_PRIO
REM echo [DEBUG ENTERED :get_priority_of_specific_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
REM echo [DEBUG] :get_priority_of_specific_process powershell processes:
REM powershell -NoLogo -ExecutionPolicy Bypass -Sta -NonInteractive -command "(Get-CimInstance Win32_Process)"
ECHO *** entered '%priority_lib_tmp_file_path%' :get_priority_of_specific_process
set "PRIORITY_LIB_TMP_VALUE_FILE_PID=%TEMP%\priority_lib_tmp_value_file_pid.tmp"
set "TMP_VAL="
powershell -NoLogo -ExecutionPolicy Bypass -Sta -NonInteractive -command "(Get-Process -Id %~1).PriorityClass.ToString()" > "!PRIORITY_LIB_TMP_VALUE_FILE_PID!"
set /p TMP_VAL=<"!PRIORITY_LIB_TMP_VALUE_FILE_PID!"
del /f "!PRIORITY_LIB_TMP_VALUE_FILE_PID!" >nul 2>&1
set "%~2=!TMP_VAL!"
REM echo [DEBUG] :get_priority_of_specific_process Process Id=%1 PRIORITY=!TMP_VAL!
ECHO *** exiting '%priority_lib_tmp_file_path%' :get_priority_of_specific_process
goto :eof

REM ------------------------------------------------------------------
:set_priority_of_specific_process
REM p1 = PID to set
REM p2 = priority level (Idle, BelowNormal, Normal, AboveNormal, High, RealTime)
REM Example: call priority_lib.bat :set_priority_of_specific_process 1234 AboveNormal
REM echo [DEBUG ENTERED :set_priority_of_specific_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
ECHO *** entered '%priority_lib_tmp_file_path%' :set_priority_of_specific_process
powershell -NoLogo -ExecutionPolicy Bypass -Sta -NonInteractive -command "(Get-Process -Id %~1).PriorityClass = '%~2'"
ECHO *** exiting '%priority_lib_tmp_file_path%' :set_priority_of_specific_process
goto :eof

REM ------------------------------------------------------------------
:ensure_minimum_priority_of_specific_process
REM p1 = PID to set
REM p2 = minimum priority to ensure (Idle, BelowNormal, Normal, AboveNormal, High, RealTime)
REM Example: call priority_lib.bat :ensure_minimum_priority_of_specific_process 1234 AboveNormal
REM echo [DEBUG ENTERED :ensure_minimum_priority_of_specific_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
ECHO *** entered '%priority_lib_tmp_file_path%' :ensure_minimum_priority_of_specific_process
call :get_priority_of_specific_process %~1 TMP_CURPRIO
REM Map priority names to numbers for comparison: higher number = higher priority
set "TMP_PRIO_NUM=0"
if /i "!TMP_CURPRIO!"=="Idle" set "TMP_PRIO_NUM=1"
if /i "!TMP_CURPRIO!"=="BelowNormal" set "TMP_PRIO_NUM=2"
if /i "!TMP_CURPRIO!"=="Normal" set "TMP_PRIO_NUM=3"
if /i "!TMP_CURPRIO!"=="AboveNormal" set "TMP_PRIO_NUM=4"
if /i "!TMP_CURPRIO!"=="High" set "TMP_PRIO_NUM=5"
if /i "!TMP_CURPRIO!"=="RealTime" set "TMP_PRIO_NUM=6"
set "TMP_TARGET_NUM=0"
if /i "%~2"=="Idle" set "TMP_TARGET_NUM=1"
if /i "%~2"=="BelowNormal" set "TMP_TARGET_NUM=2"
if /i "%~2"=="Normal" set "TMP_TARGET_NUM=3"
if /i "%~2"=="AboveNormal" set "TMP_TARGET_NUM=4"
if /i "%~2"=="High" set "TMP_TARGET_NUM=5"
if /i "%~2"=="RealTime" set "TMP_TARGET_NUM=6"
REM Compare and raise if needed
if !TMP_PRIO_NUM! lss !TMP_TARGET_NUM! (
    call :set_priority_of_specific_process %~1 %~2
)
set "TMP_CURPRIO="
set "TMP_PRIO_NUM="
set "TMP_TARGET_NUM="
ECHO *** exiting '%priority_lib_tmp_file_path%' :ensure_minimum_priority_of_specific_process
goto :eof

REM ------------------------------------------------------------------
:show_priority_of_specific_process
REM p1 = PID to query
REM Example: call priority_lib.bat :show_priority_of_specific_process 1234
REM write_host to ensure output occurs correctly
REM echo [DEBUG ENTERED :show_priority_of_specific_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
REM echo [DEBUG :show_priority_of_specific_process] Showing PriorityClass for incoming PID = %~1 
ECHO *** entered '%priority_lib_tmp_file_path%' :show_priority_of_specific_process
powershell -NoLogo -ExecutionPolicy Bypass -Sta -NonInteractive -command "(Get-Process -Id %~1).PriorityClass"
ECHO *** exiting '%priority_lib_tmp_file_path%' :show_priority_of_specific_process
goto :eof

REM ------------------------------------------------------------------
:get_priority_of_local_process
REM p1 = variable name to set in calling script (e.g., LOCALPRIO)
REM Convenience wrapper: gets priority of current CMD process
REM Example: call priority_lib.bat :get_priority_of_local_process PROC_PRIO
REM echo [DEBUG ENTERED :get_priority_of_local_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
ECHO *** entered '%priority_lib_tmp_file_path%' :get_priority_of_local_process
set "%~1="
call :get_PID_of_local_process TMP_PID
call :get_priority_of_specific_process !TMP_PID! %~1
set "TMP_PID="
ECHO *** exiting '%priority_lib_tmp_file_path%' :get_priority_of_local_process
goto :eof

REM ------------------------------------------------------------------
:set_priority_of_local_process
REM p1 = priority level (Idle, BelowNormal, Normal, AboveNormal, High, RealTime)
REM Example: call priority_lib.bat :set_priority_of_local_process AboveNormal
REM echo [DEBUG ENTERED :set_priority_of_local_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
ECHO *** entered '%priority_lib_tmp_file_path%' :set_priority_of_local_process
call :get_PID_of_local_process TMP_PID
call :set_priority_of_specific_process !TMP_PID! %~1
set "TMP_PID="
ECHO *** exiting '%priority_lib_tmp_file_path%' :set_priority_of_local_process
goto :eof

REM ------------------------------------------------------------------
:ensure_minimum_priority_of_local_process
REM p1 = minimum priority to ensure (Idle, BelowNormal, Normal, AboveNormal, High, RealTime)
REM Example: call priority_lib.bat :ensure_minimum_priority_of_local_process AboveNormal
REM echo [DEBUG ENTERED :ensure_minimum_priority_of_local_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
ECHO *** entered '%priority_lib_tmp_file_path%' :ensure_minimum_priority_of_local_process
call :get_priority_of_local_process TMP_CURPRIO
REM Map priority names to numbers for comparison: higher number = higher priority
set "TMP_PRIO_NUM=0"
if /i "!TMP_CURPRIO!"=="Idle" set "TMP_PRIO_NUM=1"
if /i "!TMP_CURPRIO!"=="BelowNormal" set "TMP_PRIO_NUM=2"
if /i "!TMP_CURPRIO!"=="Normal" set "TMP_PRIO_NUM=3"
if /i "!TMP_CURPRIO!"=="AboveNormal" set "TMP_PRIO_NUM=4"
if /i "!TMP_CURPRIO!"=="High" set "TMP_PRIO_NUM=5"
if /i "!TMP_CURPRIO!"=="RealTime" set "TMP_PRIO_NUM=6"
set "TMP_TARGET_NUM=0"
if /i "%~1"=="Idle" set "TMP_TARGET_NUM=1"
if /i "%~1"=="BelowNormal" set "TMP_TARGET_NUM=2"
if /i "%~1"=="Normal" set "TMP_TARGET_NUM=3"
if /i "%~1"=="AboveNormal" set "TMP_TARGET_NUM=4"
if /i "%~1"=="High" set "TMP_TARGET_NUM=5"
if /i "%~1"=="RealTime" set "TMP_TARGET_NUM=6"
REM Compare and raise if needed
if !TMP_PRIO_NUM! lss !TMP_TARGET_NUM! (
    call :set_priority_of_local_process %~1
)
set "TMP_CURPRIO="
set "TMP_PRIO_NUM="
set "TMP_TARGET_NUM="
ECHO *** exiting '%priority_lib_tmp_file_path%' :ensure_minimum_priority_of_local_process
goto :eof

REM ------------------------------------------------------------------
:show_priority_of_local_process
REM Prints priority of the local CMD process
REM Example: call priority_lib.bat :show_priority_of_local_process
REM echo [DEBUG ENTERED :show_priority_of_local_process] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
ECHO *** entered '%priority_lib_tmp_file_path%' :show_priority_of_local_process
set "TMP_PID="
call :get_PID_of_local_process TMP_PID
REM echo [DEBUG :show_priority_of_local_process] TMP_PID = !TMP_PID!
call :show_priority_of_specific_process !TMP_PID!
set "TMP_PID="
ECHO *** exiting '%priority_lib_tmp_file_path%' :show_priority_of_local_process
goto :eof
