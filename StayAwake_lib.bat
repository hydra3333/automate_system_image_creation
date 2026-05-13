@echo off
REM ===============================================================
REM STAY AWAKE  MANAGEMENT LIBRARY FOR BATCH SCRIPTS
REM ---------------------------------------------------------------
REM Usage:
REM   CALL StayAwake_lib.bat :label param1 param2 ...
REM 
REM Notes:
REM   - DO NOT USE SETLOCAL in this library; variables persist in the caller
REM   - All routines accept variable names to set values in the calling script
REM   - Retains -Sta for PowerShell for future COM or STA-requiring calls
REM ===============================================================

REM ==========================================================================================================
REM echo [DEBUG Entered StayAwake_lib.bat] with p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
if "%~1" equ "" goto :eof
REM
set "StayAwake_tmp_file_path=%~dpnx0"
set "_GOTO_LABEL=%~1"
shift
REM echo [DEBUG] goto !_GOTO_LABEL! with p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
goto %_GOTO_LABEL%
goto :eof
REM ==========================================================================================================

REM ------------------------------------------------------------------
:start_StayAwake
REM Usage:
REM   CALL StayAwake_lib.bat :start_StayAwake param1 param2 ...
REM
REM echo [DEBUG ENTERED :start_StayAwake] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
REM set header to date and time and computer name
ECHO *** entered '%StayAwake_tmp_file_path%' :start_StayAwake
CALL :get_header_String "header"
set "StayAwake_SourceExe=C:\SOFTWARE\Smart_Stay_Awake\Smart_Stay_Awake.exe"
set "StayAwake_SourceIcon=C:\SOFTWARE\Smart_Stay_Awake\Smart_Stay_Awake_icon.png"
set "StayAwake_Local_path=C:\TEMP\"
set "StayAwake_Local_filename=Smart_Stay_Awake_!header!.exe"
set "StayAwake_LocalExe=%StayAwake_Local_path%%StayAwake_Local_filename%"
set "StayAwake_LocalIcon=%StayAwake_Local_path%Smart_Stay_Awake_icon.png"
REM
ECHO copy "%StayAwake_SourceExe%" "%StayAwake_LocalExe%"
copy /B /V /Z /Y "%StayAwake_SourceExe%" "%StayAwake_LocalExe%"
ECHO copy /B /V /Z /Y "%StayAwake_SourceIcon%" "%StayAwake_LocalIcon%" 
copy /B /V /Z /Y "%StayAwake_SourceIcon%" "%StayAwake_LocalIcon%"
REM Spawn (nowait) the stay awake exe
echo start "%StayAwake_LocalExe%" "%StayAwake_LocalExe%" --icon "%StayAwake_LocalIcon%" --for "4h"
start "%StayAwake_LocalExe%" "%StayAwake_LocalExe%" --icon "%StayAwake_LocalIcon%" --for "4h"
ECHO *** exiting '%StayAwake_tmp_file_path%' :start_StayAwake
goto :eof

REM ------------------------------------------------------------------
:kill_StayAwake
REM Usage:
REM   CALL StayAwake_lib.bat :kill_StayAwake param1 param2 ...
REM
REM echo [DEBUG ENTERED :kill_StayAwake] p1='%1' p2='%2' p3='%3' p4='%4' p5='%5' p6='%6' p7='%7' p8='%8' 
ECHO *** entered '%StayAwake_tmp_file_path%' :kill_StayAwake
IF /I "%StayAwake_Local_filename%" == "" (
    ECHO "ERROR in :kill_StayAwake - variable 'StayAwake_Local_filename' is empty ... nothing done"
    goto :eof
)
IF /I "%StayAwake_LocalExe%" == "" (
    ECHO "ERROR in :kill_StayAwake - variable 'StayAwake_LocalExe' is empty ... nothing done"
    goto :eof
)
ECHO taskkill /t /f /im "%StayAwake_Local_filename%"
taskkill /t /f /im "%StayAwake_Local_filename%"
ECHO Wait 2 secs for the process StayAwake_Local_filename to finish ...
timeout /t 2 /nobreak >nul
IF EXIST "%StayAwake_LocalExe%" (
    ECHO DEL "%StayAwake_LocalExe%"
    DEL "%StayAwake_LocalExe%"
)
IF EXIST "%StayAwake_LocalIcon%" (
    ECHO DEL "%StayAwake_LocalIcon%" 
    DEL "%StayAwake_LocalIcon%"
)
REM dir "%StayAwake_Local_path%"
ECHO *** exiting '%StayAwake_tmp_file_path%' :kill_StayAwake
goto :eof

REM ------------------------------------------------------------------
:get_date_time_String
REM return a datetime string with spaces replaced by zeroes in format yyyy-mm-dd hh.mm.ss.hh
set "datetimestring_variable_name=%~1"
set "Datey=!DATE: =0!"
set "Timey=!TIME: =0!"
set "eval_datetime=!Datey:~10,4!-!Datey:~7,2!-!Datey:~4,2! !Timey:~0,2!.!Timey:~3,2!.!Timey:~6,2!.!Timey:~9,2!"
set "!datetimestring_variable_name!=!eval_datetime!"
goto :eof

:get_date_time_String_nospaces
REM return a datetime string with spaces replaced by zeroes and no spaces in format yyyy-mm-dd.hh.mm.ss.hh
set "ns_datetimestring_variable_name=%~1"
set "ns_eval_datetime="
CALL :get_date_time_String "ns_eval_datetime"
set "ns_eval_datetime=!ns_eval_datetime: =.!"
set "!ns_datetimestring_variable_name!=!ns_eval_datetime!"
goto :eof

:get_header_String
REM Create a Header
set "ghs_header_variable_name=%~1"
CALL :get_date_time_String_nospaces "ghs_date_time_String"
set "!ghs_header_variable_name!=!ghs_date_time_String!-!COMPUTERNAME!-%RANDOM%_%RANDOM%"
goto :eof

