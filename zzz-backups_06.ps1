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
[CmdletBinding(SupportsShouldProcess=$true, DefaultParameterSetName='Do')]
param(
    [Parameter(Mandatory = $true)]
    [string] $Target_Drives_List,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0,500)]
    [int]    $Headroom_PCT = 30,
    
    # mutually exclusive cleanup toggles
    [Parameter(ParameterSetName='Do')]      # by putting each switch in a different set, you make them mutually exclusive
    [switch]$CleanupBeforehand,
    [Parameter(ParameterSetName='Skip')]    # by putting each switch in a different set, you make them mutually exclusive
    [switch]$NoCleanupBeforehand,
    
    [string] $AbortFile = "$env:TEMP\ABORT_BACKUP.flag"
)

# FInd out whether to cleanup beforehand via mutually exclusive switches, defaulting to Do (true)
$DoCleanupBeforehand = switch ($PSCmdlet.ParameterSetName) {
  'Do'    { $true }
  'Skip'  { $false }
  default { $true }   # default behavior when neither switch is supplied
}

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
function cleanup_c_windows_temp {
    <#
      .SYNOPSIS
        cleanup TEMP folders, cache folders, restore points, etc

      .OUTPUTS
        $true
    #>
    $tempPath = "C:\Windows\TEMP"
    if (Test-Path $tempPath) {
        try {
            Write-Host "Cleaning folder $tempPath ..." -ForegroundColor White
            # Get item count before cleanup (for reporting)
            $itemCount = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object).Count
            # Get size before cleanup (for reporting)
            $beforeSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            Write-Host "$tempPath ($('{0:N1}' -f $itemCount) items) ($('{0:N1}' -f $beforeSize) MB)" -NoNewline
            Trace ("Remove-Item -Path ""$tempPath\*"" -Recurse -Force -ErrorAction SilentlyContinue")
            Remove-Item -Path "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
            $afterSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            $freed = $beforeSize - $afterSize
            Write-Host "  Cleaned ($('{0:N1}' -f $freed) MB freed)" -ForegroundColor Green
        } catch {
            Write-Host "WARNING ONLY: Error cleaning $tempPath : $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "WARNING ONLY: $tempPath folder unavailable for cleaning" -ForegroundColor Yellow
    }
    Check-Abort
    return $true
}

function cleanup_c_temp_for_every_user {
    <#
      .SYNOPSIS
        cleanup user TEMP folders for every user

      .OUTPUTS
        $true
    #>
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
                $beforeSize = ($listing | Measure-Object -Property Length -Sum).Sum / 1MB
                Write-Host "User: $userName Folder: $tempPath\* ($('{0:N1}' -f $itemCount) items) ($('{0:N1}' -f $beforeSize) MB) before Cleaning " -NoNewline
                Trace ("Remove-Item ""$tempPath\*"" -Recurse -Force -ErrorAction SilentlyContinue")
                Remove-Item "$tempPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                $afterSize = (Get-ChildItem $tempPath -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
                $freed = $beforeSize - $afterSize
                Write-Host "  Cleaned ($('{0:N1}' -f $freed) MB freed)" -ForegroundColor Green
            } catch {
                Write-Host "WARNING ONLY: Error cleaning TEMP for $userName : $($_.Exception.Message)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "WARNING ONLY: User: $userName - No TEMP folder" -ForegroundColor Yellow
        }
    }
    Write-Host "TEMP folders cleanup completed for all users" -ForegroundColor Cyan
    Check-Abort
    return $true
}

function clear_browser_data_for_all_users {
    <#
      .SYNOPSIS
        cleanup browser data (Chrome, Edge, Firefox) for every user

      .OUTPUTS
        $true
    #>
    Write-Host 'Stopping running browsers to avoid file locks...'
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
        } else { Write-Host '  Firefox: no profile root found' -ForegroundColor Yellow }
      } catch {
        Write-Host ("  Firefox: " + $_.Exception.Message) -ForegroundColor Red
      }
    }
    Write-Host 'Browser cache cleanup completed.' -ForegroundColor Cyan
    Check-Abort
    return $true
}

function empty_recycle_bins {
    try {
        Write-Host 'Emptying Recycle Bin for C: drive' -ForegroundColor White
        Trace ("Clear-RecycleBin -DriveLetter C -Force -ErrorAction Continue")
        Clear-RecycleBin -DriveLetter C -Force -ErrorAction Continue
        Write-Host 'Emptied Recycle Bin for C: successfully.' -ForegroundColor Green
    } catch {
        Write-Warning "WARNING ONLY: Failed to Empty Recycle Bin for C: drive : $($_.Exception.Message)"
        return $false
    }
    Check-Abort
    try {
        Write-Host 'Emptying Recycle Bins on all attached drives' -ForegroundColor White
        Trace ("Clear-RecycleBin -Force -ErrorAction Continue")
        Clear-RecycleBin -Force -ErrorAction Continue
        Write-Host 'Emptied Bins on all attached drives successfully.' -ForegroundColor Green
    } catch {
        Write-Warning "WARNING ONLY: Failed to Empty Recycle Bins on all attached drives : $($_.Exception.Message)"
        return $false
    }
    Write-Host 'Emptying Recycle Bins on all attached drives completed.' -ForegroundColor Cyan
    Check-Abort
    return $true
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
    Write-Host ("Cleaning up Drives using cleanmgr /sagerun:{0} " -f $SageRunId) -ForegroundColor White
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
    $argList = @("/sagerun:$SageRunId")
    # --- Run cleanmgr
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
        Write-Warning 'No drive free-space measurements were captured.'
    }
    if ($exitCode -eq 0) {
        Write-Host ("Cleanup Drives using cleanmgr /sagerun:{0} completed successfully." -f $SageRunId) -ForegroundColor Cyan
        return $true
    } else {
        Write-Warning ("cleanmgr /sagerun:{0} exited with code {1}." -f $SageRunId, $exitCode)
        Write-Host "Cleanup Drives using cleanmgr /sagerun:{0} exited with code {1}." -f $SageRunId, $exitCode -ForegroundColor Yellow
        return $false
    }
}





# ================================ Main ======================================
Write-Header ("Starting process. Target Drives: '{0}'  Headroom: {1}%" -f $Target_Drives_List, $Headroom_PCT)

if ($Debug) {
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

Trace ("validTargets: {0}" -f (($validTargets | ForEach-Object { $_ }) -join ', '))

if (-not $validTargets -or $validTargets.Count -eq 0) {
    Write-Host ''
    Write-Error 'No valid target drives remain (either invalid or insufficient space).'
    exit $EXIT.PRECHECK
}

#Write-Host ''
Write-Host ('Valid Target Drives (with space): {0}' -f ($validTargets -join ', ')) -ForegroundColor Green
Write-Host ''

Check-Abort

if ($DoCleanupBeforehand) {
    $return_status = cleanup_c_windows_temp
    $return_status = cleanup_c_temp_for_every_user
    $return_status = clear_browser_data_for_all_users
    $return_status = empty_recycle_bins
    #$return_status = run_disk_cleanup_using_cleanmgr_profile -SageRunId $sageset_profile -MeasureDrives (@('C') + @($validTargets) | ForEach-Object { ($_.TrimEnd(':','\')) + ':' } | Select-Object -Unique ) -RequireConfiguredProfile
    $return_status = run_disk_cleanup_using_cleanmgr_profile -SageRunId $sageset_profile -MeasureDrives (@('C') + @($validTargets) | ForEach-Object { ($_.TrimEnd(':','\')) + ':' } | Select-Object -Unique )
}

Check-Abort


# ============================ Where to add work =============================
# At this point you have:
#   - $validTargets    : array of 'X:' drives that passed all checks
#   - $estimate        : object with BaseEstimate_Bytes and RequiredWithHeadroom_Bytes
#
# Example skeleton for doing the actual backup (left commented out):
# foreach ($t in $validTargets) {
#     try {
#         Write-Host ("Starting wbadmin to {0} ..." -f $t) -ForegroundColor Yellow
#         $proc = Start-Process -FilePath 'wbadmin.exe' -ArgumentList @(
#                     'start','backup',
#                     "-backupTarget:$t",
#                     '-include:C:',
#                     '-allCritical',
#                     '-quiet'
#                 ) -Wait -PassThru -NoNewWindow
#         if ($proc.ExitCode -ne 0) {
#             Write-Warning ("wbadmin failed on {0} with code {1}" -f $t, $proc.ExitCode)
#         } else {
#             Write-Host ("wbadmin completed OK on {0}" -f $t) -ForegroundColor Green
#         }
#     } catch {
#         Write-Error ("wbadmin exception on {0}: {1}" -f $t, $_.Exception.Message)
#     }
#     Check-Abort
# }

Unregister-Event -SourceIdentifier ConsoleCancelEvent -ErrorAction SilentlyContinue | Out-Null
exit $EXIT.OK
