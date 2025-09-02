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
[CmdletBinding()]   # optional but nice
param(
    [Parameter(Mandatory = $true)]
    [string] $Target_Drives_List,

    [Parameter(Mandatory = $false)]
    [int]    $Headroom_PCT = 30,
    [switch] $NoCleanupBeforehand,
    [string] $AbortFile = "$env:TEMP\ABORT_BACKUP.flag"
)
# Gate for our Trace Helpers
$script:IsVerbose = $VerbosePreference -eq 'Continue'

# Trace helpers
function Trace([string]$Message) {
    if ($script:IsVerbose) { Write-Host "[VERBOSE] $Message" -ForegroundColor DarkGray }
}

function Dump-Object($Object, [string]$Label = "") {
    if (-not $script:IsVerbose) { return }
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
        $reason = @("Drive $Drive looks OK.")
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
    param([Parameter(Mandatory = $true)][ValidateRange(0, 500)][int] $Headroom_Pct)

    Trace ("Get-ImageSizeEstimate: headroom={0}%" -f $Headroom_Pct)

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

    $required = [math]::Ceiling( $base * (1 + ($Headroom_Pct / 100.0)) )

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
$estimate = Get-ImageSizeEstimate -Headroom_Pct $Headroom_PCT

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

if (-not $NoCleanupBeforehand) 
}

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

exit $EXIT.OK
