<#
.SYNOPSIS
  Validate backup target drives and compute required free space with headroom.

  powershell -NoProfile -ExecutionPolicy Bypass -File "C:\000-Essential-tasks\zzz-backups_02.ps1" -Target_Drives_List "D: E: F: G: T: I: Y:" -Headroom_PCT 35 -Verbose

.PARAMETER Target_Drives_List
  Mandatory string of drive tokens: e.g. 'D: E: G' or 'D G: E:\'

.PARAMETER Headroom_PCT
  Optional integer percentage of headroom applied on top of estimated image size.

.PARAMETER [switch] $NoCleanupBeforehand
  Optional switch indicating whether to cleanup TEMP folders, cache folders, restore points, etc, before doing the System Image Backup

.PARAMETER Verbose (a builtin)
  Optional boolean. When true, prints detailed flow + object dumps.

.NOTES
  Exits only if:
    - Not running as Administrator
    - Headroom_PCT is invalid
    - No valid drives remain after validation
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory = $true)]
    [string] $Target_Drives_List,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,500)]
    [int] $Headroom_PCT = 30,

    # Purge toggles (independent pair)
    [switch]$PurgeRestorePoints,
    [switch]$NoPurgeRestorePoints,

    # Cleanup toggles (independent pair)
    [switch]$CleanupBeforehand,
    [switch]$NoCleanupBeforehand,

    [string] $AbortFile = "$env:TEMP\ABORT_BACKUP.flag"
)

#----------------------------------------------------------------------------------------
# ---- Validate per-pair mutual exclusivities
if ($PurgeRestorePoints.IsPresent -and $NoPurgeRestorePoints.IsPresent) {
    throw "Choose either -PurgeRestorePoints or -NoPurgeRestorePoints, not both."
}
if ($CleanupBeforehand.IsPresent -and $NoCleanupBeforehand.IsPresent) {
    throw "Choose either -CleanupBeforehand or -NoCleanupBeforehand, not both."
}

# ---- Compute effective booleans with the required defaults
$DoPurgeRestorePointsBeforehand =
    if ($PurgeRestorePoints)          { $true }
    elseif ($NoPurgeRestorePoints)    { $false }
    else                              { $false }    # default: no purge

$DoCleanupBeforehand =
    if ($CleanupBeforehand)       { $true }
    elseif ($NoCleanupBeforehand) { $false }
    else                          { $true }         # default: do cleanup
#----------------------------------------------------------------------------------------

# Gate for our Trace Helpers
# 1. from commandline -Verbose
$script:IsVerbose = $VerbosePreference -eq 'Continue'

# 2. our own flag to edit in this script, useful during development/debugging
#$script:enable_trace = $true
$script:want_trace = $false

# Trace helpers
function Trace([string]$Message) {
    if ($script:IsVerbose -or $script:enable_trace) { Write-Host "[VERBOSE] $Message" -ForegroundColor DarkGray }
}

function Dump-Object($Object, [string]$Label = "") {
    if (-not ($script:IsVerbose -or $script:enable_trace)) { return }
    if ($Label) { Write-Host "[VERBOSE] $Label =" -ForegroundColor DarkGray }
    try {
        $Object | Format-List * | Out-String -Width 500 |
            ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
    } catch {
        Write-Host "[VERBOSE] <unprintable object>" -ForegroundColor DarkGray
    }
}

# ============================ Settings / Globals ============================
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$sageset_profile       = 1  # pre-defined profile number, saved by the user, for cleanmgr to cleanup the system
                            # require that profile 1 has been configured previously via:
                            #    cleanmgr.exe /sageset:1

$EXIT = @{
  OK            = 0
  GENERIC       = 1
  BAD_ARGS      = 2
  PRECHECK      = 3
  NO_SPACE      = 4
  NOT_NTFS      = 5
  REFUSED       = 6
  VSS_FAIL      = 7
  WBADMIN_FAIL  = 8
  FORMAT_FAIL   = 9
  CANCEL_CTRL_C = 90
  CANCEL_FLAG   = 91
  CANCEL_KEY    = 92
  UNKNOWN       = 99
}

# Drives we will never allow as targets
$Forbidden_Target_Drives = @('C:', 'E:', 'U:')

# Cancellation state
$script:UserCancelled = $false

# ================================ Helpers ==================================

Function do_pause {
    Write-Host "Press any key to continue..."
    $x = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Write-Header([string]$Text) {
    Write-Host ('=' * 78) -ForegroundColor DarkGray
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor DarkGray
}

function Abort([string]$Message, [int]$Code = $EXIT.GENERIC) {
    if ($Message) { Write-Error $Message }
    exit $Code
}

# Ctrl+C and "Q" support (best effort)
Register-EngineEvent -SourceIdentifier ConsoleCancelEvent -Action {
    $script:UserCancelled = $true
    $eventArgs.Cancel = $true
    Write-Warning 'CTRL+C detected - will abort at next checkpoint...'
} | Out-Null

function Check-Abort {
    if ($script:UserCancelled) {
        Abort 'Cancelled by user (Ctrl+C).' $EXIT.CANCEL_CTRL_C
    }
    if ($AbortFile -and (Test-Path -LiteralPath $AbortFile)) {
        Abort "Abort flag file found: $AbortFile" $EXIT.CANCEL_FLAG
    }
    try {
        if ([Console]::KeyAvailable) {
            $k = [Console]::ReadKey($true)
            if ($k.Key -eq 'Q') {
                Abort 'Cancelled by user (Q).' $EXIT.CANCEL_KEY
            }
        }
    } catch { }
}

function Require-Admin([string]$Why = 'Creating System Image backups') {
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
                    [Security.Principal.WindowsIdentity]::GetCurrent()
               )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Abort "$Why requires Administrator. Re-run elevated." $EXIT.PRECHECK
    }
}

function Normalize-DriveToken {
    <#
      .SYNOPSIS
        Normalize a user-supplied token to 'X:' format or return $null.

      .EXAMPLES
        'd'     -> 'D:'
        'e:'    -> 'E:'
        'g:\'   -> 'G:'
        'bad1'  -> $null
    #>
    param([string]$Token)
    if (-not $Token) { return $null }
    $t = $Token.Trim()
    if     ($t -match '^[a-zA-Z]$')        { $t += ':' }
    elseif ($t -match '^[a-zA-Z]:\\?$')    { $t  = $t.Substring(0,2) }
    $t = $t.ToUpper()
    if ($t -match '^[A-Z]:$') { return $t }
    return $null
}

# ========================== Validation / Estimation =========================
function Test-TargetDrive {
    <#
      .SYNOPSIS
        Validate a single target drive. Returns details; never exits.
        returns a result object with details.            

      .OUTPUTS
        [pscustomobject] with:
          Drive         : 'X:'
          Exists        : [bool]  # PSDrive/FileSystem exists
          Ready         : [bool]  # Root path resolves
          Forbidden     : [bool]
          FileSystem    : [string] # e.g., 'NTFS', 'exFAT', etc (if available)
          IsNTFS        : [bool]   # $true when FileSystem -eq 'NTFS'
          FreeBytes     : [Int64]  # -1 if unknown
          Valid         : [bool]   # summary: acceptable target?
          Message       : [string] # reason summary
    #>
    param([Parameter(Mandatory = $true)][string] $Drive)

    Trace ("Test-TargetDrive: start for {0}" -f $Drive)

    $dl           = $Drive[0]
    $root         = "$Drive\"
    $exists       = $false
    $ready        = $false
    $forbidden    = $false
    $fs           = $null
    $isNTFS       = $false
    $freeBytes    = [Int64](-1)
    $valid        = $false
    $reason       = @()

    try {
        #$Trace ("psd = Get-PSDrive -Name $dl -PSProvider FileSystem -ErrorAction Stop")
        $psd = Get-PSDrive -Name $dl -PSProvider FileSystem -ErrorAction Stop
        $exists = $true
        $freeBytes = [Int64]$psd.Free
    } catch {
        $reason += "Drive $Drive not found or not a FileSystem drive."
        $out = [pscustomobject]@{
            Drive=$Drive; Exists=$exists; Ready=$ready; Forbidden=$forbidden
            FileSystem=$fs; IsNTFS=$isNTFS; FreeBytes=$freeBytes
            Valid=$valid; Message=($reason -join ' ')
        }
        Dump-Object $out "Test-TargetDrive result ($Drive)"
        return $out
    }

    if (-not (Test-Path -LiteralPath $root)) {
        $reason += "Drive $Drive is not ready/mounted."
        $out = [pscustomobject]@{
            Drive=$Drive; Exists=$exists; Ready=$ready; Forbidden=$forbidden
            FileSystem=$fs; IsNTFS=$isNTFS; FreeBytes=$freeBytes
            Valid=$valid; Message=($reason -join ' ')
        }
        Dump-Object $out "Test-TargetDrive result ($Drive)"
        return $out
    }

    $ready = $true

    if ($Drive -in $Forbidden_Target_Drives) {
        $forbidden = $true
        $reason   += "Drive $Drive is forbidden by policy."
    }
    # Filesystem check (best effort)
    try {
        $vol = Get-Volume -DriveLetter $dl -ErrorAction Stop
        if ($vol) {
            $fs     = $vol.FileSystem
            $isNTFS = ($fs -eq 'NTFS')
        }
    } catch { }

    if (-not $isNTFS) {
        $reason += if ($fs) { "Drive $Drive is $fs; NTFS required." }
                   else     { "Drive $Drive filesystem unknown; NTFS required." }
    }

    if ($exists -and $ready -and (-not $forbidden) -and $isNTFS) {
        $valid  = $true
        $reason = @("Drive $Drive structurally valid.")
    }

    $result = [pscustomobject]@{
        Drive      = $Drive
        Exists     = $exists
        Ready      = $ready
        Forbidden  = $forbidden
        FileSystem = $fs
        IsNTFS     = $isNTFS
        FreeBytes  = $freeBytes
        Valid      = $valid
        Message    = ($reason -join ' ')
    }

    Dump-Object $result "Test-TargetDrive result ($Drive)"
    return $result
}

function Get-ImageSizeEstimate {
    <#
      .SYNOPSIS
        Estimate System Image Backup size for C: then apply headroom.
      .OUTPUTS
        [pscustomobject] with:
          UsedC_Bytes
          Excluded_Bytes
          CriticalAllowance_Bytes
          BaseEstimate_Bytes       # (UsedC - Excluded + Allowance) * 1.10
          RequiredWithHeadroom_Bytes  # BaseEstimate * (1 + headroom%)
    #>
    param([Parameter(Mandatory = $true)][ValidateRange(0, 500)][int] $Headroom_PCT)

    Trace ("Get-ImageSizeEstimate: headroom={0}%" -f $Headroom_PCT)

    # Used bytes on C:
    $usedC = (Get-PSDrive -Name C -PSProvider FileSystem).Used
    # Exclude some large system files if present
    $exclude =
        @('C:\pagefile.sys','C:\hiberfil.sys','C:\swapfile.sys') |
        Where-Object   { Test-Path -LiteralPath $_ } |
        ForEach-Object { (Get-Item -LiteralPath $_).Length } |
        Measure-Object -Sum |
        Select-Object -ExpandProperty Sum
    if (-not $exclude) { $exclude = 0 }

    $criticalAllowance = 2GB
    $base = [math]::Ceiling( (($usedC - $exclude + $criticalAllowance) * 1.10) )
    if ($base -lt 0) { $base = 0 }

    $required = [math]::Ceiling( $base * (1 + ($Headroom_PCT / 100.0)) )

    $out = [pscustomobject]@{
        UsedC_Bytes                 = [Int64]$usedC
        Excluded_Bytes              = [Int64]$exclude
        CriticalAllowance_Bytes     = [Int64]$criticalAllowance
        BaseEstimate_Bytes          = [Int64]$base
        RequiredWithHeadroom_Bytes  = [Int64]$required
    }
    Dump-Object $out "Image Size Estimate"
    return $out
}

function Test-FreeSpaceForImage {
    <#
      .SYNOPSIS
        For a given drive, check free space against a required size.

      .OUTPUTS
        [pscustomobject] with:
          Drive
          FreeBytes
          RequiredBytes
          Fits
          Message
    #>
    param(
        [Parameter(Mandatory = $true)][string] $Drive,
        [Parameter(Mandatory = $true)][Int64]  $RequiredBytes
    )

    Trace ("Test-FreeSpaceForImage: {0}, need {1:N1} GB" -f $Drive, ($RequiredBytes/1GB))

    $dl = $Drive[0]
    $free = [Int64](-1)

    try {
        $psd  = Get-PSDrive -Name $dl -PSProvider FileSystem -ErrorAction Stop
        $free = [Int64]$psd.Free
    } catch {
        $res = [pscustomobject]@{
            Drive=$Drive; FreeBytes=$free; RequiredBytes=$RequiredBytes
            Fits=$false; Message="Drive $Drive not found."
        }
        Dump-Object $res "FreeSpace result ($Drive)"
        return $res
    }

    $fits = ($free -ge $RequiredBytes)
    $msg  = if ($fits) { 'Drive has sufficient free space.' }
            else       { 'Insufficient free space.' }

    $result = [pscustomobject]@{
        Drive         = $Drive
        FreeBytes     = $free
        RequiredBytes = $RequiredBytes
        Fits          = $fits
        Message       = $msg
    }
    Dump-Object $result "FreeSpace result ($Drive)"
    return $result
}

# ========================== Operational =========================
function Allow_publishing_of_User_Activities {
    <#  Function: Allow_publishing_of_User_Activities
        Purpose: Enable or disable Windows User Activity logging via Group Policy registry
        Parameter: [bool] $EnableFlag — if $true, explicitly enable activities; if $false, explicitly disable
        Returns: [bool] $return_code — $true if all registry writes succeed, $false otherwise
        
        According to Microsoft’s Policy CSP for Privacy, the registry value UploadUserActivities is under:
            HKLM\SOFTWARE\Policies\Microsoft\Windows\System 
        Microsoft Learn
            The “Disable Activity History” tweak in Winutil also sets:
                EnableActivityFeed = 0
                PublishUserActivities = 0
                UploadUserActivities = 0
            under the same path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\System 
        christitustech.github.io
            Disabling “Allow publishing of User Activities” via Group Policy corresponds to the same key PublishUserActivities = 0 in that path. 

    Windows 11 (25H2) is actively logging activity into ActivitiesCache.db as at 2025.11.20.
    Your directory listing shows:
        ActivitiesCache.db is ~11.8 MB, which is quite large for this database.
    The .db-wal and .db-shm files have timestamps from 19/11/2025 at 2:33–2:38 PM, 
    meaning the database was actively updated today, minutes before you ran the directory listing.
    This confirms Windows is still writing timeline/activity events, even in 25H2.
    The presence and fresh timestamps confirm ongoing writes.
    Important: The size and recency show logging is active, not legacy
    Some forensic researchers reported that in Win11 the DB remains but no new entries appear.
    Your system clearly contradicts that - it is updated in 2025.
    That means some Windows services/features are still feeding data into it.
    
    So despite Microsoft removing the old “Timeline” UI, the underlying logging mechanism
    (“User Activity” database) still exists and still logs, unless explicitly disabled.
    
    What the files mean
        ActivitiesCache.db
            This is the primary SQLite database containing the activity entries.
            11 MB is large enough to contain hundreds or thousands of events such as:
                Executable launches (apps opened)
                Document or media files accessed
                Clipboard and share events
                Some browser URL-open events (depending on app integration)
                System-level “user engagement” metadata
                Possibly activity sync metadata
        ActivitiesCache.db-wal
            Write-ahead log = actively recording new entries right now.
        ActivitiesCache.db-shm
            Shared‐memory file = used by the SQLite engine while writing/locking.
    
        Windows 11 quietly logs a lot of your activity in ActivitiesCache.db - is TRUE on your system.
        It is not necessarily every file, every app, every web page... but it is certainly logging more than people expect.
    
    Chosen: Option B - Disable via Group Policy
        This is the most reliable for Windows 10/11 Pro.
        Enable:
            Local Computer Policy -> Computer Configuration -> Administrative Templates -> System -> OS Policies -> Allow publishing of User Activities -> Disabled
        And also disable:
            “Allow upload of User Activities”
            “Enable Activity Feed”
    
        Allow publishing of User Activities → Disabled
        Allow upload of User Activities → Disabled
        Enable Activity Feed → Disabled
        Equivalent registry modifications using PowerShell:
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Value 0 -Type DWord
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" 
    #>
    param (
        [bool] $EnableFlag
    )
    # High-level status message
    if ($EnableFlag) {
        Write-Host "Enabling Windows Activity Logging (PublishUserActivities, UploadUserActivities, EnableActivityFeed) via registry policy." -ForegroundColor Cyan
    }
    else {
        Write-Host "Disabling Windows Activity Logging (PublishUserActivities, UploadUserActivities, EnableActivityFeed) via registry policy." -ForegroundColor Cyan
    }
    $return_code = $true
    # Define registry path for policy keys
    $policyKeyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    # Ensure the registry key exists
    try {
        if (-not (Test-Path -Path $policyKeyPath)) {
            Write-Host "Registry path '$policyKeyPath' does not exist. Creating it." -ForegroundColor Green
            New-Item -Path $policyKeyPath -Force | Out-Null
        }
        else {
            Trace "Registry path '$policyKeyPath' already exists, will use it."
        }
    }
    catch {
        Write-Warning "ERROR: Failed to create or access registry path '$policyKeyPath', nothing done. Exception: $_" 
        $return_code = $false
    }
    if ($return_code) {
        # Prepare the values to write; 0=Disable, 1=Enable
        $values = @{
            "PublishUserActivities" = if ($EnableFlag) { [int] 1 } else { [int] 0 }
            "UploadUserActivities"  = if ($EnableFlag) { [int] 1 } else { [int] 0 }
            "EnableActivityFeed"    = if ($EnableFlag) { [int] 1 } else { [int] 0 }
        }
        # Write each DWORD value
        foreach ($name in $values.Keys) {
            $data = $values[$name]
            try {
                Trace "Setting registry value '$name' = $data (DWORD) in $policyKeyPath"
                Set-ItemProperty -Path $policyKeyPath -Name $name -Value $data -Type DWord -Force
            }
            catch {
                Write-Warning "ERROR: Failed to set registry value '$name' to $data in $policyKeyPath. Exception: $_"
                $return_code = $false
            }
        }
    }
    # Summary / final status
    if ($return_code) {
        $enabled_or_disabled = if ($EnableFlag) { "enabled" } else { "disabled" }
        Write-Host "Successfully $enabled_or_disabled Windows Activity Logging via registry policy." -ForegroundColor Green
    }
    else {
        Write-Warning "One or more registry reads/writes failed. Specified Activity Logging policy may not be fully applied."
        Trace ("Allow_publishing_of_User_Activities completed with status: {0}" -f $return_code)
    }
    return $return_code
}

function cleanup_c_windows_temp {
    <#
      .SYNOPSIS
        cleanup TEMP folders, cache folders, restore points, etc

      .OUTPUTS
        $true
    #>
    $return_code = $false
    $tempPath = "C:\Windows\TEMP"
    if (Test-Path $tempPath) {
        try {
            Write-Host "Cleaning folder $tempPath ..." -ForegroundColor Cyan
            # Get item count before cleanup (for reporting)
            $itemCount = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
            # Get size before cleanup (for reporting)
            $beforeSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            Write-Host "$tempPath ($('{0:N1}' -f $itemCount) items) ($('{0:N1}' -f $beforeSize) MB)" -NoNewline
            Trace ("Remove-Item -Path `"$tempPath\*`" -Recurse -Force -ErrorAction SilentlyContinue")
            Remove-Item -Path "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
            $afterSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            $freed = $beforeSize - $afterSize
            Write-Host "  Cleaned ($('{0:N1}' -f $freed) MB freed)" -ForegroundColor Green
            $return_code = $true
        } catch {
            Write-Warning "WARNING ONLY: Error cleaning $tempPath : $($_.Exception.Message)"
        }
    } else {
         Write-Warning "WARNING ONLY: $tempPath folder unavailable for cleaning"
    }
    Check-Abort
    return $return_code
}

function cleanup_c_temp_for_every_user {
    <#
    .SYNOPSIS
      cleanup user TEMP folders for every user

    .OUTPUTS
      $true
    #>
    $return_code = $false
    $userDirs = Get-ChildItem "C:\Users" -Directory | Where-Object {
        $_.Name -notin @("Public", "Default", "Default User", "All Users") -and
        $_.Name -notlike "defaultuser*"
    }
    Write-Host "Cleaning TEMP folders for $($userDirs.Count) users..."  -ForegroundColor Cyan
    foreach ($userDir in $userDirs) {
        $userName = $userDir.Name
        $tempPath = "C:\Users\$userName\AppData\Local\Temp"
        if (Test-Path $tempPath) {
            try {
                # Get item count and size before cleanup (for reporting)
                $listing = Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue
                $itemCount = $listing.Count
                #$beforeSize = ($listing | Measure-Object -Property Length -Sum).Sum / 1MB
                $filesBefore = Get-ChildItem $tempPath -Recurse -Force -File -ErrorAction SilentlyContinue
                $beforeSize  = ($filesBefore | Measure-Object -Property Length -Sum).Sum / 1MB
                Write-Host "User: $userName Folder: $tempPath\* ($('{0:N1}' -f $itemCount) items) ($('{0:N1}' -f $beforeSize) MB) before Cleaning " -NoNewline
                Trace ("Remove-Item `"$tempPath\*`" -Recurse -Force -ErrorAction SilentlyContinue")
                Remove-Item "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                #$afterSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
                $afterFiles = Get-ChildItem $tempPath -Recurse -Force -File -ErrorAction SilentlyContinue
                $afterSize  = ($afterFiles | Measure-Object -Property Length -Sum).Sum / 1MB
                $freed = $beforeSize - $afterSize
                Write-Host "  Cleaned ($('{0:N1}' -f $freed) MB freed)" -ForegroundColor Green
                $return_code = $true
            } catch {
                 Write-Warning "WARNING ONLY: Error cleaning TEMP for $userName : $($_.Exception.Message)"
            }
        } else {
             Write-Warning "WARNING ONLY: User: $userName - No TEMP folder"
        }
    }
    Write-Host "TEMP folders cleanup completed for all users" -ForegroundColor Cyan
    Check-Abort
    return $return_code
}

function clear_browser_data_for_all_users {
    <#
      .SYNOPSIS
        cleanup browser data (Chrome, Edge, Firefox) for every user

      .OUTPUTS
        $true on success (exit code 0), otherwise $false.
    #>
    $return_code = $false
    Write-Host 'Stopping running browsers to avoid file locks...' -ForegroundColor Cyan
    Get-Process chrome, msedge, msedgewebview2, firefox, opera, brave -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Check-Abort
    # Get all user directories, excluding system accounts
    $userDirs = Get-ChildItem 'C:\Users' -Directory | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') -and $_.Name -notlike 'defaultuser*' }
    Write-Host ("Cleaning caches for " + $userDirs.Count + " user(s)...") -ForegroundColor Cyan
    foreach($userDir in $userDirs){
      $userName = $userDir.Name
      Write-Host (" Cleaning User: " + $userName) -ForegroundColor White
      Check-Abort
      # ---------- Chrome ----------
      try {
        $chromeRoot = "C:\Users\$userName\AppData\Local\Google\Chrome\User Data"
        if(Test-Path $chromeRoot){
          $profiles = Get-ChildItem $chromeRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+|Guest Profile)$' }
          $cleaned = 0
          foreach($p in $profiles){
            $paths = @(
              (Join-Path $p.FullName 'Cache\*'),
              (Join-Path $p.FullName 'Cache\Cache_Data\*'),
              (Join-Path $p.FullName 'Media Cache\*'),
              (Join-Path $p.FullName 'Code Cache\*'),
              (Join-Path $p.FullName 'GPUCache\*'),
              (Join-Path $p.FullName 'Service Worker\CacheStorage\*'),
              (Join-Path $p.FullName 'Service Worker\ScriptCache\*')
            )
            foreach($pp in $paths){
                Trace ("Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue")
                Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue
            }
            # as network houses cookies, deleting cookies logs you out of all browser websites
            # Network: clear everything except cookies & key state
            #$net = Join-Path $p.FullName 'Network'
            #if (Test-Path $net) {
            #  Get-ChildItem $net -Force -ErrorAction SilentlyContinue |
            #    Where-Object { $_.Name -notlike 'Cookies*' -and $_.Name -ne 'TransportSecurity' -and $_.Name -notlike 'Reporting and NEL*' -and $_.Name -ne 'Network Persistent State' } |
            #    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            #}
            $cleaned++
          }
          Write-Host ('  Chrome: cleaned ' + $cleaned + ' profile(s) for ' +  $userName) -ForegroundColor Green
          $return_code = $true
        } else {
          Write-Host ('  Chrome: no profile root found for ' + $userName) -ForegroundColor Yellow
        }
      } catch {
          Write-Host ("  Chrome: " + $_.Exception.Message) -ForegroundColor Red
      }
      # ---------- Edge (Chromium) ----------
      try {
        $edgeRoot = "C:\Users\$userName\AppData\Local\Microsoft\Edge\User Data"
        if(Test-Path $edgeRoot){
          $profiles = Get-ChildItem $edgeRoot -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(Default|Profile \d+|Guest Profile)$' }
          $cleaned = 0
          foreach($p in $profiles){
            $paths = @(
              (Join-Path $p.FullName 'Cache\*'),
              (Join-Path $p.FullName 'Cache\Cache_Data\*'),
              (Join-Path $p.FullName 'Media Cache\*'),
              (Join-Path $p.FullName 'Code Cache\*'),
              (Join-Path $p.FullName 'GPUCache\*'),
              (Join-Path $p.FullName 'Service Worker\CacheStorage\*'),
              (Join-Path $p.FullName 'Service Worker\ScriptCache\*')
            )
            foreach($pp in $paths){
                Trace ("Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue")
                Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue
            }
            # as network houses cookies, deleting cookies logs you out of all browser websites
            # Network: clear everything except cookies & key state
            #$net = Join-Path $p.FullName 'Network'
            #if (Test-Path $net) {
            #  Get-ChildItem $net -Force -ErrorAction SilentlyContinue |
            #    Where-Object { $_.Name -notlike 'Cookies*' -and $_.Name -ne 'TransportSecurity' -and $_.Name -notlike 'Reporting and NEL*' -and $_.Name -ne 'Network Persistent State' } |
            #    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            #}
            $cleaned++
          }
          Write-Host ('  Edge: cleaned ' + $cleaned + ' profile(s) for ' +  $userName) -ForegroundColor Green
          $return_code = $true
        } else {
          Write-Host ('  Edge: no profile root found for ' + $userName) -ForegroundColor Yellow
        }
      } catch {
        Write-Host ("  Edge: " + $_.Exception.Message) -ForegroundColor Red
      }
      # ---------- Firefox ----------
      try {
        $ffLocal = "C:\Users\$userName\AppData\Local\Mozilla\Firefox\Profiles"
        if(Test-Path $ffLocal){
          $profiles = Get-ChildItem $ffLocal -Directory -ErrorAction SilentlyContinue
          $cleaned = 0
          foreach($p in $profiles){
            $paths = @(
              (Join-Path $p.FullName 'cache2\*'),
              (Join-Path $p.FullName 'startupCache\*'),
              (Join-Path $p.FullName 'thumbnails\*'),
              (Join-Path $p.FullName 'shader-cache\*'),
              (Join-Path $p.FullName 'jumpListCache\*')
            )
            foreach($pp in $paths){
                Trace ("Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue")
                Remove-Item $pp -Recurse -Force -ErrorAction SilentlyContinue
            }
            $cleaned++
          }
          Write-Host ('  Firefox: cleaned ' + $cleaned + ' profile(s) for ' +  $userName) -ForegroundColor Green
          $return_code = $true
        } else { Write-Host '  Firefox: no profile root found' -ForegroundColor Yellow }
      } catch {
        Write-Host ("  Firefox: " + $_.Exception.Message) -ForegroundColor Red
      }
    }
    Write-Host 'Browser cache cleanup completed.' -ForegroundColor Cyan
    Check-Abort
    return $return_code
}

function empty_recycle_bins {
    <#
    .SYNOPSIS
      empties recycle nins on all attached rrives

    .OUTPUTS
      $true on success (exit code 0), otherwise $false.
    #>
    $return_code = $false
    try {
        Write-Host 'Emptying Recycle Bin for drive C:' -ForegroundColor Cyan
        Trace ("Clear-RecycleBin -DriveLetter C -Force -ErrorAction Continue")
        Clear-RecycleBin -DriveLetter C -Force -ErrorAction Continue
        Write-Host 'Emptied Recycle Bin for C: successfully.' -ForegroundColor Green
        $return_code = $true
    } catch {
         Write-Warning "WARNING ONLY: Failed to Empty Recycle Bin for drive C: : $($_.Exception.Message)"
    }
    Check-Abort
    try {
        Write-Host 'Emptying Recycle Bins on all attached drives' -ForegroundColor Cyan
        Trace ("Clear-RecycleBin -Force -ErrorAction Continue")
        Clear-RecycleBin -Force -ErrorAction Continue
        Write-Host 'Emptied Bins on all attached drives successfully.' -ForegroundColor Green
        $return_code = $true
    } catch {
        Write-Warning "WARNING ONLY: Failed to Empty Recycle Bins on all attached drives : $($_.Exception.Message)"
    }
    Write-Host 'Emptying Recycle Bins on all attached drives completed.' -ForegroundColor Cyan
    Check-Abort
    return $return_code
}

function get_cleanmgr_profile_status {
    <# 
    .SYNOPSIS
      Check if a CleanMgr /sagerun profile is configured.

    .PARAMETER SageRunId
      Integer profile id used with /sagerun:n and /sageset:n.

    .OUTPUTS
      [pscustomobject] with:
        SageRunId, FlagName, ConfiguredItems, Exists
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0,9999)]
        [int] $SageRunId
    )
    $flagName = ('StateFlags{0:D4}' -f $SageRunId)
    $baseKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
    $count    = 0
    try {
        $items = Get-ChildItem -LiteralPath $baseKey -ErrorAction Stop
    } catch {
        return [pscustomobject]@{
            SageRunId        = $SageRunId
            FlagName         = $flagName
            ConfiguredItems  = 0
            Exists           = $false
        }
    }
    foreach ($it in $items) {
        try {
            $p = Get-ItemProperty -Path $it.PSPath -Name $flagName -ErrorAction SilentlyContinue
            if ($null -ne $p.$flagName) { $count++ }
        } catch { }
    }
    [pscustomobject]@{
        SageRunId        = $SageRunId
        FlagName         = $flagName
        ConfiguredItems  = $count
        Exists           = ($count -gt 0)
    }
}

function run_disk_cleanup_using_cleanmgr_profile {
    <#
    .SYNOPSIS
      Run Disk Cleanup with a given /sagerun profile, with safety checks
      and a free-space before/after report.

    .PARAMETER SageRunId
      Integer profile id (must have been configured via cleanmgr /sageset:<id>).

    .PARAMETER MeasureDrives
      Drives to measure free space on before/after (e.g. 'C','D').    

    .PARAMETER RequireConfiguredProfile
      If set, refuse to run when the specified profile has no configured items.

    .OUTPUTS
      $true on success (exit code 0), otherwise $false.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0,9999)]
        [int]      $SageRunId,
        [string[]] $MeasureDrives = @('C:'),
        [switch]   $RequireConfiguredProfile
    )
    Trace ("run_disk_cleanup_using_cleanmgr_profile: SageRunId=$SageRunId MeasureDrives=$MeasureDrives RequireConfiguredProfile=$RequireConfiguredProfile")
    Write-Host ("Cleaning up Drives using cleanmgr /sagerun:{0} " -f $SageRunId) -ForegroundColor Cyan
    Check-Abort
    # Ensure cleanmgr exists
    Trace ("cmd = Get-Command -Name 'cleanmgr.exe' -ErrorAction SilentlyContinue")
    $cmd = Get-Command -Name 'cleanmgr.exe' -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Abort 'cleanmgr.exe not found (Desktop Experience may be missing).' $EXIT.PRECHECK
    }
    # Profile sanity
    Trace ("status = get_cleanmgr_profile_status -SageRunId $SageRunId")
    $status = get_cleanmgr_profile_status -SageRunId $SageRunId
    if (-not $status.Exists) {
        $msg = "SageRun profile $SageRunId appears unconfigured (no $($status.FlagName) entries)."
        if ($RequireConfiguredProfile) {
            Abort $msg $EXIT.BAD_ARGS
        } else {
            Write-Warning $msg
        }
    }
    # --- Measure free space BEFORE
    $before = @{}
    foreach ($d in $MeasureDrives) {
        Trace ("BEFORE 'foreach (d in MeasureDrives)' ... d=$d MeasureDrives=$MeasureDrives")
        try {
            $letter = ($d.TrimEnd(':','\'))[0]
            Trace ("psd = Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop")
            $psd    = Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop
            $before["${letter}:"] = [int64]$psd.Free
            Trace ("Before[{0}] = {1:N1} GB" -f "$($letter):", ($psd.Free/1GB))
        } catch {
             Write-Warning ("WARNING ONLY: Failed to measure free space before cleanmgr for drive {0}: {1}" -f $d, $_.Exception.Message)
            continue
        }
    }
    # --- Run cleanmgr
    $argList = @("/sagerun:$SageRunId")
    $exitCode = 0 # was 1
    try {
        Trace ("proc = Start-Process -FilePath {0} -ArgumentList {1} -Wait -PassThru -NoNewWindow" -f $cmd.Source, ($argList -join ' '))
        $proc     = Start-Process -FilePath $cmd.Source -ArgumentList $argList -Wait -PassThru -NoNewWindow
        $exitCode = $proc.ExitCode
    } catch {
         Write-Warning ("WARNING ONLY: Failed to run_disk_cleanup_using_cleanmgr_profile: {0}" -f $_.Exception.Message)
        # proceed to after-measurement anyway
    }
    Check-Abort
    # --- Measure free space AFTER
    $after = @{}
    foreach ($d in $MeasureDrives) {
        Trace ("AFTER in 'foreach (d in MeasureDrives)' ... d=$d MeasureDrives=$MeasureDrives")
        try {
            $letter = ($d.TrimEnd(':','\'))[0]
            Trace ("psd = Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop")
            $psd    = Get-PSDrive -Name $letter -PSProvider FileSystem -ErrorAction Stop
            $after["${letter}:"] = [int64]$psd.Free
            Trace ("After [{0}] = {1:N1} GB" -f "$($letter):", ($psd.Free/1GB))
        } catch {
            Write-Warning ("WARNING ONLY: Failed to measure free space after cleanmgr for drive {0}: {1}" -f $d, $_.Exception.Message)
            continue
        }
    }
    # --- Build and always print a table (even if Freed is 0.0 or n/a)
    $rows = @(
        foreach ($driveKey in ($before.Keys + $after.Keys | Select-Object -Unique | Sort-Object)) {
            Trace ("INSIDE loop rows= ... foreach (driveKey in (before.Keys + after.Keys | Select-Object -Unique | Sort-Object)) ... currently driveKey=$driveKey before.Keys=$($before.Keys) after.Keys=$($after.Keys)")
            $b = if ($before.ContainsKey($driveKey)) { [double]$before[$driveKey]/1GB } else { $null }
            $a = if ($after.ContainsKey($driveKey))  { [double]$after[$driveKey]/1GB }  else { $null }
            $f = if ($a -ne $null -and $b -ne $null) { [math]::Round($a - $b, 1) } else { $null }
            [pscustomobject]@{
                Drive        = $driveKey
                FreeBeforeGB = if ($b -ne $null) { [math]::Round($b,1) } else { $null }
                FreeAfterGB  = if ($a -ne $null) { [math]::Round($a,1) } else { $null }
                FreedGB      = $f
            }
        }
    )
    #Write-Host ''
    Write-Host 'Disk Cleanup free-space report:' -ForegroundColor Cyan
    Trace ("About to do if (rows.Count -gt 0) ... rows.Count=$($rows.Count)")
    if ($rows.Count -gt 0) {
        Trace ("... Inside if (rows.Count -gt 0) ... rows.Count=$($rows.Count)")
        # Render 'n/a' for nulls so you always see a row
        $rows |
            Sort-Object Drive |
            Select-Object Drive,
                          @{n='FreeBeforeGB';e={ if ($_.FreeBeforeGB -ne $null) { '{0:N1}' -f $_.FreeBeforeGB } else { 'n/a' } }},
                          @{n='FreeAfterGB'; e={ if ($_.FreeAfterGB  -ne $null) { '{0:N1}' -f $_.FreeAfterGB  } else { 'n/a' } }},
                          @{n='FreedGB';     e={ if ($_.FreedGB      -ne $null) { '{0:N1}' -f $_.FreedGB      } else { 'n/a' } }} |
            Format-Table -AutoSize |
            Out-Host   # <-- this makes it display even when output is being captured
    } else {
        Write-Warning 'WARNING ONLY: No drive free-space measurements were captured.'
    }
    if ($exitCode -eq 0) {
        Write-Host ("Cleanup Drives using cleanmgr /sagerun:{0} completed successfully." -f $SageRunId) -ForegroundColor Green
        $return_code = $true
    } else {
        Write-Warning ("WARNING ONLY: Cleanup Drives using cleanmgr /sagerun:{0} exited with code: {1}." -f $SageRunId, $exitCode)
        $return_code = $false
    }
    return $return_code
}

function list_current_restore_points_on_C {
    <#
    .SYNOPSIS
      List current stsrem rstore points on C

    .OUTPUTS
      Listing of current retore points on drive C:
    #>
    Write-Host 'List of current restore points on drive C:' -ForegroundColor Cyan
    try {
        Trace ("process = Start-Process -FilePath 'vssadmin.exe' -ArgumentList @(`"list`", `"shadows`", `"/for=C:`") -Wait -PassThru -NoNewWindow")
        $process = Start-Process -FilePath 'vssadmin.exe' -ArgumentList @("list", "shadows", "/for=C:") -Wait -PassThru -NoNewWindow
        $exitCode = $process.ExitCode
        if ($exitCode -ne 0) {
            Write-Warning ("WARNING ONLY: vssadmin List current restore points on drive C: failed with code: {0}" -f $exitCode)
            $return_code = $false
        } else {
            Write-Host 'Listed current restore points on drive C: successfully.' -ForegroundColor Green
            $return_code = $true
        }
    } catch {
        Write-Warning ("WARNING ONLY: Failed to List current restore points on drive C: : {0}" -f $_.Exception.Message)
        $return_code = $false
    }
    Check-Abort
    Write-Host 'List current restore points on drive C: completed.' -ForegroundColor Cyan
    return $return_code
}

function enable_system_restore_protection_on_C {
    <#
    .SYNOPSIS
      Enable System Restore Protection on drive C:

    .OUTPUTS
      $true on success (exit code 0), otherwise $false.
    #>
    Write-Host 'Enabling System Restore Protection on drive C: (if disabled)...' -ForegroundColor Cyan
    # Ensure cmdlet exists on this system (Server Core or stripped images may lack it)
    $enableCmd = Get-Command -Name Enable-ComputerRestore -ErrorAction SilentlyContinue
    if (-not $enableCmd) {
        $result.Message = 'Enable-ComputerRestore cmdlet not available on this system.'
        Write-Warning ("WARNING ONLY: System Restore Protection 'Enable-ComputerRestore cmdlet' not available on this system : {0}" -f $result.Message)
        return $false
    }
    $needEnable = $false
    # Get the Registry hint (present even when SR is disabled)
    try {
        Trace ("srKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue")
        $srKey = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -ErrorAction SilentlyContinue
        if ($srKey -and ($srKey.DisableSR -eq 1)) {
            $needEnable = $true
        }
    } catch {
        Write-Warning ("WARNING ONLY: Failed to Get the Registry hint (present even when System Restore is disabled) : {0}" -f $_.Exception.Message)
    }
    # Fallback to CIM test (may be null if never enabled)
    # CIM check (per-drive); if never configured, may be null
    if (-not $needEnable) {
        try {
            Trace ("cfg = Get-CimInstance -Namespace 'root/default' -ClassName SystemRestoreConfig -ErrorAction SilentlyContinue | Where-Object { `$_.Drive -eq 'C:' }")
            $cfg = Get-CimInstance -Namespace 'root/default' -ClassName SystemRestoreConfig -ErrorAction SilentlyContinue | Where-Object { $_.Drive -eq 'C:' }
            if (-not $cfg -or $cfg.RPSessionInterval -lt 0) {
                $needEnable = $true
            }
        } catch {
            Write-Warning ("WARNING ONLY: Failed the fallback System Restore Get-CimInstance check : {0}" -f $_.Exception.Message)
        }
    }
    if ($needEnable) {
        try {
            Trace ("Enable-ComputerRestore -Drive 'C:' -ErrorAction SilentlyContinue")
            Enable-ComputerRestore -Drive 'C:' -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            Write-Host 'System Restore Protection enabled on drive C:' -ForegroundColor Green
            $return_code = $true
        } catch {
            Write-Warning ("WARNING ONLY: Failed to enable System Restore Protection on drive C: : {0}" -f $($_.Exception.Message))
            $return_code = $false
        }
    } else {
        Write-Host 'System Restore Protection already enabled on drive C:' -ForegroundColor Green
        $return_code = $true
    }
    Write-Host 'Enable System Restore Protection on drive C: completed.' -ForegroundColor Cyan
    Check-Abort
    return $return_code
}

function resize_shadow_storage_limit_on_C {
    <#
    .SYNOPSIS
      Resizes the shadow storage limit on the drive C: to the nominated number of gigabytes.
      It is the disk space cap for Windows’ Volume Shadow Copy Service (VSS) on drive C:
      When Windows makes restore points / previous versions, it stores the changed-data (“diffs”)
      in a hidden shadow storage area under C:\System Volume Information.
      "Resize the shadow storage limit to N GB" means:
        Set the maximum space VSS is allowed to use on C: to N gigabytes.
        If the diff area grows past that limit, older restore points are purged automatically.
        Raising the limit keeps more restore points; lowering it may immediately delete older ones to get under the new cap.
        This does not resize the drive C: partition; it just changes the quota for VSS data.
        Shadow storage must live on an NTFS volume; you can keep it on C: or even place it on another NTFS drive.

    .PARAMETER shadow_storage_limit_gb
      The number of gigagytes to resize the shadow storage limit to.

    .OUTPUTS
      $true on success (exit code 0), otherwise $false.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateRange(0,200)]
        [int] $shadow_storage_limit_gb
    )
    $shadow_storage_limit_gb_string = '{0}GB' -f ([int]$shadow_storage_limit_gb)
    Write-Host ("Resize Shadow Storage limit on drive C: to {0}..." -f $shadow_storage_limit_gb_string) -ForegroundColor Cyan
    try {
        Trace ("process = Start-Process -FilePath 'vssadmin.exe' -ArgumentList `@(`"Resize`", `"ShadowStorage`", `"/For=C:`", `"/On=C:`", `"/MaxSize=$shadow_storage_limit_gb_string`"")
        $process = Start-Process -FilePath 'vssadmin.exe' -ArgumentList @("Resize", "ShadowStorage", "/For=C:", "/On=C:", "/MaxSize=$shadow_storage_limit_gb_string") -Wait -PassThru -NoNewWindow
        $exitCode = $process.ExitCode
        if ($exitCode -ne 0) {
            Write-Warning ("WARNING ONLY: Failed to Resize Shadow Storage limit on drive C: to {0} exited with exit code : {1}" -f $shadow_storage_limit_gb_string, $exitCode)
            $return_code = $false
        } else {
            Write-Host ("Resize Shadow Storage limit on drive C: to {0} completed successfully." -f $shadow_storage_limit_gb_string) -ForegroundColor Green
            $return_code = $true
        }
    } catch {
        Write-Warning ("WARNING ONLY: Failed to Resize Shadow Storage limit to {0} on drive C: : {1}" -f $shadow_storage_limit_gb_string, $_.Exception.Message)
        $return_code = $false
    }
    Check-Abort
    return $return_code
}

function PurgeRestorePoints_on_C {
    <#
    .SYNOPSIS
      Purges all System Restore Points on the drive C:

    .OUTPUTS
      $true on success (exit code 0), otherwise $false.
    #>
    Write-Host ("Purging System Restore Points on drive C: ..." ) -ForegroundColor Cyan
    try {
        Trace ("process = Start-Process -FilePath 'vssadmin.exe' -ArgumentList `@(`"delete`", `"shadows`", `"/For=C:`", `"/all`", `"/quiet`"")
        $process = Start-Process -FilePath 'vssadmin.exe' -ArgumentList @("delete", "shadows", "/For=C:", "/all", "/quiet") -Wait -PassThru -NoNewWindow
        $exitCode = $process.ExitCode
        if ($exitCode -ne 0) {
            Write-Warning ("WARNING ONLY: Failed to Purge System Restore Points on drive C: exited with exit code : {0}" -f $exitCode)
            $return_code = $false
        } else{
            Write-Host ("Purge System Restore Points on drive C: completed successfully.") -ForegroundColor Green
            $return_code = $true
        }
    } catch {
        Write-Warning ("WARNING ONLY: Failed to Purge System Restore Points on drive C: : {0}" -f $_.Exception.Message)
        $return_code = $false
    }
    Check-Abort
    return $return_code
}

function SetSystemRestoreFrequency {
    <#
    .SYNOPSIS
        Create, update, or delete the SystemRestorePointCreationFrequency registry value.

    .PARAMETER Action
        "Set"    (default) -> Set the value to the proposed minutes.
        "Delete" -> Remove the value to fall back to the Microsoft default (1440 minutes).
        eg  SetSystemRestoreFrequency -Action Set -Minutes 5   # Set to 5 minutes
            SetSystemRestoreFrequency -Action Delete           # Delete value (revert to 1440)

    .PARAMETER Minutes
        Minutes between restore point creation (only used when Action=Set). Default = 1
    #>
    param(
        [ValidateSet("Set","Delete")]
        [string] $Action = "Set",
        [int] $Minutes = 1
    )
    # Set default values
    $fn                          = $MyInvocation.MyCommand.Name
    $SRP_Registry_previous_value = 1440   # Microsoft default if missing
    $SRP_Registry_new_value      = $null
    $SRP_RegistryPath            = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore"
    $SRP_RegistryValueName       = "SystemRestorePointCreationFrequency"
    $return_code                 = $true
    #
    # Basic validation
    if ($Action -eq "Set" -and $Minutes -lt 1) {
        Write-Warning "Invalid Minutes value '$Minutes'. It must be a positive integer."
        return [PSCustomObject]@{
            ReturnCode          = $false
            Action              = $Action
            PreviousVal_minutes = $SRP_Registry_previous_value
            NewVal_minutes      = $SRP_Registry_new_value
            ErrorMessage        = "Invalid Minutes: $Minutes"
        }
    }
    #
    if ($Action -eq "Set") {
        Write-Host "ACTION: $fn $Action registry key $SRP_RegistryPath - $SRP_RegistryValueName = $Minutes minutes" -ForegroundColor White
    }
    elseif ($Action -eq "Delete") {
        Write-Host "ACTION: $fn $Action registry key $SRP_RegistryPath - $SRP_RegistryValueName" -ForegroundColor White
    }
    else {
        Write-Warning "WARNING ONLY: $fn - invalid action : $Action ... nothing done"
        return [PSCustomObject]@{
            ReturnCode          = $false
            Action              = $Action
            PreviousVal_minutes = $SRP_Registry_previous_value
            NewVal_minutes      = $SRP_Registry_new_value
            ErrorMessage        = "Invalid Action $Action for $fn"
        }
    }
    # Ensure the registry key path exists (defensive)
    try {
        Trace "$fn Test-Path $SRP_RegistryPath)"
        if (-not (Test-Path $SRP_RegistryPath)) {
            Trace "$fn New-Item -Path $SRP_RegistryPath -Force | Out-Null)"
            New-Item -Path $SRP_RegistryPath -Force | Out-Null
        }
    } catch {
        Write-Warning "WARNING ONLY: Unable to ensure registry key path $SRP_RegistryPath exists : $($_.Exception.Message)"
        return [PSCustomObject]@{
            ReturnCode          = $false
            Action              = $Action
            PreviousVal_minutes = $SRP_Registry_previous_value
            NewVal_minutes      = $SRP_Registry_new_value
            ErrorMessage        = $_.Exception.Message
        }
    }
    # --- Get and show the current value if it exists
    try {
        Trace "$fn Get-ItemProperty -Path $SRP_RegistryPath -Name $SRP_RegistryValueName -ErrorAction Stop"
        $current = Get-ItemProperty -Path $SRP_RegistryPath -Name $SRP_RegistryValueName -ErrorAction Stop
        $SRP_Registry_previous_value = [int]$current.$SRP_RegistryValueName
        Write-Host "Existing -Path $SRP_RegistryPath -Name $SRP_RegistryValueName value=$SRP_Registry_previous_value minutes"
    } catch {
        Write-Host "$SRP_RegistryValueName does not exist in $SRP_RegistryPath, using Microsoft default value $SRP_Registry_previous_value as previous value"
    }
    if ($Action -eq "Set") {
        # --- Set/Update the registry value
        try {
            Trace "$fn New-ItemProperty -Path $SRP_RegistryPath -Name $SRP_RegistryValueName -PropertyType DWord -Value $Minutes -Force | Out-Null"
            New-ItemProperty -Path $SRP_RegistryPath -Name $SRP_RegistryValueName -PropertyType DWord -Value $Minutes -Force | Out-Null
            $SRP_Registry_new_value = $Minutes
            Write-Host "$SRP_RegistryValueName (re)set to $Minutes minute(s) in $SRP_RegistryPath"
        } catch {
            Write-Warning "WARNING ONLY: Unable to set registry $SRP_RegistryValueName in $SRP_RegistryPath : $($_.Exception.Message)"
            $return_code = $false
        }
    }
    elseif ($Action -eq "Delete") {
        # --- Check if the value exists
        $exists = $false
        try {
            if (Get-ItemProperty -Path $SRP_RegistryPath -Name $SRP_RegistryValueName -ErrorAction Stop) {
                $exists = $true
            }
        } catch {
            Write-Host "$SRP_RegistryValueName not found in $SRP_RegistryPath, nothing to remove."
        }
        # --- Attempt removal if it exists
        if ($exists) {
            try {
                Trace "Remove-ItemProperty -Path $SRP_RegistryPath -Name $SRP_RegistryValueName"
                Remove-ItemProperty -Path $SRP_RegistryPath -Name $SRP_RegistryValueName
                $SRP_Registry_new_value = $null  # missing -> Windows uses 1440
                Write-Host "$SRP_RegistryValueName removed from $SRP_RegistryPath. Windows will fall back to default (1440 minutes)."
            } catch {
                Write-Warning "WARNING ONLY: Unable to remove registry $SRP_RegistryValueName from $SRP_RegistryPath : $($_.Exception.Message)"
                $return_code = $false
            }
        } else {
            $SRP_Registry_new_value = $null  # already at default behavior
        }
    }
    if ($return_code) {
        if ($Action -eq "Set") {
            Write-Host "Successfully completed $fn $Action registry key $SRP_RegistryPath - $SRP_RegistryValueName = $Minutes minutes" -ForegroundColor Cyan
        }
        elseif ($Action -eq "Delete") {
            Write-Host "Successfully completed $fn $Action registry key $SRP_RegistryPath - $SRP_RegistryValueName" -ForegroundColor Cyan
        }
    }
    else {
        if ($Action -eq "Set") {
            Write-Host "Unsuccessfully completed $fn $Action registry key $SRP_RegistryPath - $SRP_RegistryValueName = $Minutes minutes" -ForegroundColor Yellow
        }
        elseif ($Action -eq "Delete") {
            Write-Host "Unsuccessfully completed $fn $Action registry key $SRP_RegistryPath - $SRP_RegistryValueName" -ForegroundColor Yellow
        }
    }
    # Return structured info
    return [PSCustomObject]@{
        ReturnCode          = $return_code
        Action              = $Action
        PreviousVal_minutes = $SRP_Registry_previous_value
        NewVal_minutes      = $SRP_Registry_new_value
    }
}

function Test-VSSHealth {
    <#
    .SYNOPSIS
      Check VSS health and trace individual writer states
    #>
    Write-Host "Checking VSS health..." -ForegroundColor Cyan
    # Check VSS service
    $vss = Get-Service -Name VSS
    Write-Host "VSS Service Status: $($vss.Status)" -ForegroundColor $(if($vss.Status -eq 'Running'){'Green'}else{'Red'})
    Trace "VSS Service: Status=$($vss.Status), StartType=$($vss.StartType)"
    # Get detailed VSS writers information
    $writersOutput = vssadmin list writers
    # Parse writer details
    $writers = @()
    $currentWriter = $null
    foreach ($line in $writersOutput -split "`r?`n") {
        if ($line -match "Writer name: '(.+)'") {
            if ($currentWriter) {
                $writers += $currentWriter
            }
            $currentWriter = @{
                Name = $matches[1]
                State = $null
                LastError = $null
            }
        }
        elseif ($line -match "State: \[(\d+)\] (.+)" -and $currentWriter) {
            $currentWriter.State = $matches[2]
        }
        elseif ($line -match "Last error: (.+)" -and $currentWriter) {
            $currentWriter.LastError = $matches[1]
        }
    }
    # Add the last writer
    if ($currentWriter) {
        $writers += $currentWriter
    }
    # Count and report
    $totalCount = $writers.Count
    $stableWriters = $writers | Where-Object { $_.State -eq 'Stable' }
    $unstableWriters = $writers | Where-Object { $_.State -ne 'Stable' }
    $stableCount = $stableWriters.Count
    Write-Host "VSS Writers: $totalCount total, $stableCount stable" -ForegroundColor $(if($totalCount -eq $stableCount){'Green'}else{'Yellow'})
    # Trace stable writers
    if ($stableCount -gt 0) {
        Trace "=== STABLE VSS Writers ($stableCount) ==="
        foreach ($writer in $stableWriters) {
            Trace "  [OK] $($writer.Name)"
        }
    }
    # Trace unstable writers with details
    if ($unstableWriters.Count -gt 0) {
        Trace "=== UNSTABLE VSS Writers ($($unstableWriters.Count)) ==="
        foreach ($writer in $unstableWriters) {
            $errorInfo = if ($writer.LastError) { " | Error: $($writer.LastError)" } else { "" }
            Trace "  [PROBLEM] $($writer.Name) | State: $($writer.State)$errorInfo"
            Write-Warning "[PROBLEM] VSS Writer problem: $($writer.Name) - State: $($writer.State)"
        }
    }
    # If writers are problematic, try restarting VSS
    if ($totalCount -ne $stableCount) {
        Write-Host "**********************************************************" -ForegroundColor Yellow
        Write-Host "Some VSS writers are not stable. Restarting VSS service..." -ForegroundColor Yellow
        Write-Host "**********************************************************" -ForegroundColor Yellow
        Trace "*************************************************************"
        Trace "Attempting VSS service restart to recover unstable writers..."
        Trace "*************************************************************"
        try {
            Restart-Service -Name VSS -Force
            Start-Sleep -Seconds 5
            # Re-check after restart
            $writersAfter = vssadmin list writers
            $stableAfter = ([regex]::Matches($writersAfter, "State: \[1\] Stable")).Count
            Trace "After VSS restart: $stableAfter stable writers (was $stableCount)"
            if ($stableAfter -gt $stableCount) {
                Write-Host "***************************************************************" -ForegroundColor Yellow
                Write-Host "VSS restart improved writer health: $stableCount -> $stableAfter stable" -ForegroundColor Green
                Write-Host "***************************************************************" -ForegroundColor Yellow
                Trace "***************************************************************"
                Trace "VSS restart improved writer health: $stableCount -> $stableAfter stable"
                Trace "***************************************************************"
            } else {
                Write-Warning "*******************************************************************************"
                Write-Warning "[PROBLEM] VSS restart did not improve writer health (still $stableAfter stable)"
                Write-Warning "*******************************************************************************"
                Trace "*******************************************************************************"
                Trace "[PROBLEM] VSS restart did not improve writer health (still $stableAfter stable)"
                Trace "*******************************************************************************"
            }
        } catch {
            Write-Warning "*********************************************************************"
            Write-Warning "Failed to restart VSS service: $($_.Exception.Message)"
            Write-Warning "*********************************************************************"
            Trace "*********************************************************************"
            Trace "Failed to restart VSS service: $($_.Exception.Message)"
            Trace "*********************************************************************"
        }
    } else {
        Trace "All VSS writers are stable - no action needed"
        Write-Host "All VSS writers are stable - no action needed" -ForegroundColor Green
    }
    return $true
}

function create_restore_point_on_C {
    <#
    .SYNOPSIS
      Creates a System Restore Point on drive C: with timeout protection
    .OUTPUTS
      $true on success, otherwise $false.
    #>
    Write-Host 'Creating a System Restore Point on drive C:...' -ForegroundColor Cyan
    # Check that the cmdlet exists (on some editions it may be missing)
    try {
        $enableCmd = Get-Command -Name "Checkpoint-Computer" -ErrorAction Stop
    } catch {
        Write-Warning ("WARNING ONLY: 'Checkpoint-Computer' cmdlet not available on this system : {0}" -f $($_.Exception.Message))
        return $false
    }
    # Ensure System Protection is enabled on C: (no-op if already on)
    try {
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    } catch {
        Write-Warning ("WARNING ONLY: Could not (re)enable System Protection on drive C: : {0}" -f $($_.Exception.Message))
        # not fatal — continue, Checkpoint-Computer will still tell us if it fails
    }
    # Before attempting to create a restore point, check the health of VSS
    $return_status = Test-VSSHealth
    # ----------
    # Method 1: Try with timeout using Start-Job
    $return_code = $false
    $timeoutSeconds = 120  # 2 minutes timeout
    try {
        Write-Host "Attempting restore point creation (timeout: $timeoutSeconds seconds)..." -ForegroundColor White
        Trace ("Executing Job BLOCK: Start-Job -ScriptBlock { Checkpoint-Computer -Description 'Scripted Restore Point' -RestorePointType 'MODIFY_SETTINGS' }")
        $job = Start-Job -ScriptBlock {
            Checkpoint-Computer -Description 'Scripted Restore Point' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        }
        Trace ("Waiting for completion of Job BLOCK: Checkpoint-Computer -Description 'Scripted Restore Point' -RestorePointType 'MODIFY_SETTINGS'")
        $completed = Wait-Job -Job $job -Timeout $timeoutSeconds
        if ($completed) {
            $result = Receive-Job -Job $job -ErrorAction Stop
            Remove-Job -Job $job -Force
            Write-Host 'Created System Restore Point on drive C:' -ForegroundColor Green
            $return_code = $true
        } else {
            # Timeout occurred
            # ----------
            # Method 2: Use WMI as fallback
            Write-Warning "Checkpoint-Computer Method 1 failed : timed out after $timeoutSeconds seconds."
            Write-Warning "Trying alternative Method 2 'Use WMI as fallback'"
            Remove-Job -Job $job -Force
            # Method 2: Use WMI as fallback
            $return_code = Create-RestorePoint-WMI
        }
    } catch {
        # ----------
        # Method 2: Use WMI as fallback
        Write-Warning "Checkpoint-Computer Method 1 failed: $($_.Exception.Message)"
        Write-Warning "Trying alternative Method 2 'Use WMI as fallback'"
        Remove-Job -Job $job -Force
        $return_code = Create-RestorePoint-WMI
    }
    Write-Host 'Creation of System Restore Point on drive C: completed.' -ForegroundColor Cyan
    Check-Abort
    return $return_code
}

function Create-RestorePoint-WMI {
    <#
    .SYNOPSIS
      Alternative method using WMI to create restore point
    #>
    try {
        Write-Host "Creating Method 2 restore point via WMI..." -ForegroundColor White
        # Get SystemRestore class
        $SysRestore = Get-WmiObject -Namespace "root\default" -Class SystemRestore -ErrorAction Stop
        # Create restore point (returns 0 on success)
        $result = $SysRestore.CreateRestorePoint("Scripted Restore Point", 0, 100)
        if ($result.ReturnValue -eq 0) {
            Write-Host "Successfully created restore point via Method 2 WMI" -ForegroundColor Green
            Start-Sleep -Seconds 3
            return $true
        } else {
            Write-Warning "ERROR: Method 2 WMI CreateRestorePoint returned code: $($result.ReturnValue)"
            return $false
        }
    } catch {
        Write-Warning "ERROR: Method 2 WMI method also failed: $($_.Exception.Message)"
        return $false
    }
}

function create_system_image_backups {
    <#
    .SYNOPSIS
      Create a System Image Backup on each of a set of target drives

    .PARAMETER TargetDrives
      Target drives to create System Image Backups to (e.g. 'D','G').    

    .OUTPUTS
      $true on success (exit code 0), otherwise $false.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $TargetDrives
    )
    
    Trace ("Create a System Image Backup on each of a set of target drives TargetDrives=$TargetDrives")
    Write-Host ("Create a System Image Backup on each of a set of target drives TargetDrives=$TargetDrives") -ForegroundColor Cyan
    foreach ($TargetDrive in $TargetDrives) {
        Trace ("INSIDE 'foreach (TargetDrive in TargetDrives)' ... TargetDrive=$TargetDrive TargetDrives=$TargetDrives")
        Write-Host "Starting Create a System Image Backup of C: to $TargetDrive ..." -ForegroundColor Cyan
        try {
            Trace ("Starting Create a System Image Backup to {0} ..." -f $TargetDrive)
            Write-Host ("Starting Create a System Image Backup to {0} ..." -f $TargetDrive) -ForegroundColor white
            Trace "(proc = Start-Process -FilePath `'wbadmin.exe`' -ArgumentList `@(`'start`', `'backup`', `"-backupTarget:$TargetDrive`", `'-include:C:`', `'-allCritical`', '-quiet') -Wait -PassThru -NoNewWindow"
            $proc = Start-Process -FilePath 'wbadmin.exe' -ArgumentList @('start', 'backup', "-backupTarget:$TargetDrive", '-include:C:', '-allCritical', '-quiet') -Wait -PassThru -NoNewWindow
            if ($proc.ExitCode -ne 0) {
                Write-Error ("ERROR: Create a System Image Backup to {0} Failed with code {1}" -f $TargetDrive, $proc.ExitCode)
            } else {
                Write-Host ("Create a System Image Backup to {0} was successful." -f $TargetDrive) -ForegroundColor Green
            }
        } catch {
            Write-Error ("ERROR: Create a System Image Backup to {0} Failed: {1}" -f $TargetDrive, $_.Exception.Message)
        }
        Check-Abort
    }
    return $true
}

# ================================ Main ======================================
Write-Header ("Starting process. Target Drives: '{0}'  Headroom: {1}%" -f $Target_Drives_List, $Headroom_PCT)

if ($Debug) {
    Dump-Object $PSVersionTable "PSVersionTable"
    Dump-Object $PSBoundParameters "PSBoundParameters"
}

# 1) Admin gate
Require-Admin 'Creating a System Image backup'

# 2) Headroom validation (exit on bad input)
if (-not ($Headroom_PCT -is [int]) -or $Headroom_PCT -lt 0 -or $Headroom_PCT -gt 500) {
    Abort "Headroom_PCT must be an integer between 0 and 500." $EXIT.BAD_ARGS
}

# 3) Split and normalize the target drive list
$rawTokens = $Target_Drives_List -split '[\s,]+' | Where-Object { $_ }
Trace ("Raw tokens: {0}" -f ($rawTokens -join ', '))

$targets   = [System.Collections.Generic.List[string]]::new()
$seen      = [System.Collections.Generic.HashSet[string]]::new()

foreach ($tok in $rawTokens) {
    $norm = Normalize-DriveToken $tok
    if ($null -ne $norm) {
        if ($seen.Add($norm)) {
            $targets.Add($norm) | Out-Null
        }
    } else {
        Write-Warning "Ignoring invalid drive token: '$tok'"
    }
}

Trace ("Normalized unique targets: {0}" -f ($targets -join ', '))

if ($targets.Count -eq 0) {
    Abort "No usable drive tokens supplied after normalization." $EXIT.BAD_ARGS
}

Check-Abort

# 4) Single estimate of System Image Backup for this run
$estimate = Get-ImageSizeEstimate -Headroom_PCT $Headroom_PCT

Write-Host ('Estimated System Image (base):     {0:N1} GB' -f ($estimate.BaseEstimate_Bytes / 1GB))
Write-Host ('Required with headroom ({0}%): {1:N1} GB' -f $Headroom_PCT, ($estimate.RequiredWithHeadroom_Bytes / 1GB))
Write-Host ''

# 5) Validate each drive + free-space test
$validationResults = foreach ($d in $targets) {
    $vr = Test-TargetDrive -Drive $d
    $fr = $null
    if ($vr.Valid) {
        $fr = Test-FreeSpaceForImage -Drive $d -RequiredBytes $estimate.RequiredWithHeadroom_Bytes
    }

    $haveGB = if ($vr.FreeBytes -ge 0) { [math]::Round($vr.FreeBytes / 1GB, 1) } else { $null }
    $needGB = if ($fr) { [math]::Round($fr.RequiredBytes / 1GB, 1) } else { $null }

    # Build a clearer reason
    $reason =
        if (-not $vr.Valid) {
            $vr.Message
        }
        elseif ($fr -and -not $fr.Fits) {
            "Insufficient free space (have $haveGB GB, need $needGB GB)"
        }
        else {
            "Ready"
        }

    [pscustomobject]@{
        Drive      = $vr.Drive
        Valid      = $vr.Valid           # structural check
        Fits       = if ($fr) { $fr.Fits } else { $false }  # capacity check
        FileSystem = $vr.FileSystem
        FreeGB     = $haveGB
        NeedGB     = $needGB
        Reason     = $reason
    }
}

Dump-Object $validationResults "All validation rows"

# 6) Print a summary table
Write-Header 'Target Drive validation summary'
$validationResults |
    Sort-Object Drive |
    Format-Table Drive, Valid, Fits, FileSystem, FreeGB, NeedGB, Reason -AutoSize


# 7) Build the list of valid targets
$validTargets = $validationResults |
    Where-Object { $_.Valid -and $_.Fits } |
    Select-Object -ExpandProperty Drive

$ValidTargetDrive_list = (@($validTargets) | ForEach-Object { ($_.TrimEnd(':','\')) + ':' } | Select-Object -Unique )

Trace ("ValidTargetDrive_list: {0}" -f (($ValidTargetDrive_list | ForEach-Object { $_ }) -join ', '))

if (-not $ValidTargetDrive_list -or $ValidTargetDrive_list.Count -eq 0) {
    Write-Host ''
    Write-Error 'No valid target drives remain (either invalid or insufficient space).'
    exit $EXIT.PRECHECK
}

Write-Host ('Valid Target Drives (with enough free disk space): {0}' -f ($ValidTargetDrive_list -join ', ')) -ForegroundColor Green
Write-Host ''

Check-Abort

# Disable Windows Activity Logging via Global Policy registry keys for Win10/Win11
$return_status = Allow_publishing_of_User_Activities($false)
if (-not $return_status) {
    Write-Warning "WARNING: Could not disable Windows Activity Logging."
}

Check-Abort

$return_status = enable_system_restore_protection_on_C

Check-Abort

$return_status = resize_shadow_storage_limit_on_C "100"

Check-Abort

if ($DoPurgeRestorePointsBeforehand) {
    $return_status = PurgeRestorePoints_on_C
    Write-Host "List of Restore points on C drive after purge:"
    $return_status = list_current_restore_points_on_C
}
else {
    Write-Host "Not purging Restore Points on C drive, purging not requested: PurgeRestorePoints=$PurgeRestorePoints NoPurgeRestorePoints=$NoPurgeRestorePoints DoPurgeRestorePointsBeforehand=$DoPurgeRestorePointsBeforehand"
}

Check-Abort

#do_pause

if ($DoCleanupBeforehand) {
    $return_status = cleanup_c_windows_temp
    $return_status = cleanup_c_temp_for_every_user
    $return_status = clear_browser_data_for_all_users
    $return_status = empty_recycle_bins
    #   run_disk_cleanup_using_cleanmgr_profile   -RequireConfiguredProfile   -Verbose
    $return_status = run_disk_cleanup_using_cleanmgr_profile -SageRunId $sageset_profile -MeasureDrives @(@('C:') +  $ValidTargetDrive_list)
}

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Temporarily Set/reset the value of microsoft enforced minutes between creating consecutive System Restore Points
$result_object = SetSystemRestoreFrequency -Action Set -Minutes 1
$return_status       = $result_object.ReturnCode
$PreviousVal_minutes = $result_object.PreviousVal_minutes
$NewVal_minutes      = $result_object.NewVal_minutes
Trace ("SetSystemRestoreFrequency -Action Set -Minutes 1 result_object={0}" -f $result_object)
#
#$return_status = list_current_restore_points_on_C
$return_status = create_restore_point_on_C
$return_status = list_current_restore_points_on_C
#
$result_object = SetSystemRestoreFrequency -Action Set -Minutes $PreviousVal_minutes
$return_status = $result_object.ReturnCode
$PreviousVal_minutes_reset = $result_object.PreviousVal_minutes
Trace ("SetSystemRestoreFrequency -Action Set -Minutes 1 result_object={0}" -f $result_object)
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$return_status = create_system_image_backups $ValidTargetDrive_list

Unregister-Event -SourceIdentifier ConsoleCancelEvent -ErrorAction SilentlyContinue | Out-Null
exit $EXIT.OK
