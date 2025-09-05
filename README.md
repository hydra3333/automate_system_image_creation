# Automated Windows System Image Backup Script

![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey)
![License](https://img.shields.io/badge/license-AGPL--3.0-green) 

A PowerShell script for creating native Windows System Image backups to multiple 'target drives' with advanced validation, cleanup options, and progress step reporting.

## About Windows System Images

Windows System Image backups create complete, bit-for-bit copies of your system drive and critical boot partitions.    
These system images are 100% created by, and automatically detected by, Windows 10/11's built-in recovery tools and can restore
your entire system to exactly the state it was in when the backup was performed.

**What's included in a Windows System Image (it's a lot, and extremely handy):**
- **System partition** (typically C:) with all installed programs, settings, and user data
- **EFI System Partition (ESP)** containing boot loaders and firmware settings
- **Recovery partition** with Windows Recovery Environment (WinRE)
- **Boot Configuration Data (BCD)** and system state information
- **Any additional partitions** marked as critical for system operation

**Recovery/Restoration options using Windows System Images:**
- **Windows Recovery Environment (WinRE)** - Access via Windows `Advanced Startup Options`
- **System Image Recovery tool** - Built into Windows Backup and Restore
- **Installation Disk or Recovery Disk** - Via `Advanced Startup Options` boot from external installation media or recovery media (eg USB)
- **Automatic detection** - Windows finds and lists available system images on connected drives

This makes Windows System Images ideal for complete disaster recovery, major system changes, or migrating to new hardware, as they preserve your entire Windows installation exactly as configured.

To create a Windows System Image, you must have enough free disk space on the target drive to contain it.

## Features

- **Multi-Drive Support**: Create system image backups to multiple target drives simultaneously
- **Space Validation**: Automatically validates target drives and checks available space before backup
- **Pre-Backup Cleanup**: Optional cleanup of temp files, browser caches, and recycle bins
- **Restore Point Management**: Create restore points and optionally purge old ones
- **Drive Validation**: Ensures target drives are NTFS and have sufficient free space
- **Headroom Calculation**: Configurable safety margin for backup space requirements
- **Logging**: Detailed progress tracking and warning/error reporting
- **Admin Safety**: Requires administrator privileges with built-in validation

## Prerequisites

- **Windows Operating System** Windows 10/11 with PowerShell 5.1 or later
- **Administrator privileges** (script enforces this requirement)
- **NTFS target drives** (other filesystems are rejected)
- **Windows Backup features** enabled (wbadmin.exe available)
- **Sufficient free space** on target drives

### Windows Disk Cleanup Profile #1 Setup

For the Windows controlled Disk Cleanup feature to work optimally, pre-configure your Windows `cleanmgr` profile #1:

1. Run this as Administrator: `cleanmgr /sageset:1`
2. Select Windows Disk Cleanup categories that you want Windows to clean when requested
3. Click OK to save the profile

## Optional Pre-Imaging Cleanup Operations

- **Windows Disk Cleanup** using `cleanmgr` Profile #1 which you **must** create beforehand (google it)
- **Windows TEMP folder** cleanup
- **User TEMP folders** cleanup for all users
- **Browser cache cleanup** (Chrome, Edge, Firefox) for all users
- **Recycle bin** emptied on all drives
- **System Restore Points** removed and a new System Restore Points created

## Drive Validation

The script performs comprehensive validation of target drives:

- ✅ **Drive exists** and is accessible
- ✅ **NTFS filesystem** (required for system images)
- ✅ **Sufficient free space** (C: usage + headroom percentage)
- ✅ **Drive ready** and mounted
- ✅ **Not forbidden** (C:, E:, U: are blocked from being target drives by default inside the .ps1 script; hence edit the .ps1 script for your needs)

## Space Calculation

The script estimates backup size using:
```
Base Estimate = (C: Used Space - Excluded Files + 2GB Allowance) × 1.10
Final Required = Base Estimate × (1 + Headroom_PCT/100)
```

**Excluded files**: pagefile.sys, hiberfil.sys, swapfile.sys

## Safety Features

- **Administrator requirement** enforced
- **Drive validation** before any operations
- **Space verification** before backup starts
- **Restore point creation** before major operations
- **Ctrl+C cancellation** support
- **"Q" key cancellation** during operation
- **Abort flag file** monitoring (`$env:TEMP\ABORT_BACKUP.flag`)

## Quick Start

### Option 1: Using Batch Files to invoke the Powershell (the easy way)

1. **Download the .ps1 powershell script and Example .bat files**:
   - `111-Create_system_image_to_drives_RunAs_Admin.ps1`
   - `111-Create_system_image_to_drives_RunAs_Admin_C_to_D_E_G_T_I_Y-RunAs_Admin.bat` (with cleanup)
   - `111-Create_system_image_to_drives_RunAs_Admin_C_to_D_E_G_T_I_Y_NOcleanup-RunAs_Admin.bat` (no cleanup)

2. **Modify the batch files** to customize your chosen target drives to create System Image Backups onto:
   ```batch
   SET "TARGET_DRIVE_LIST=D: E: G:"
   ```
**NOTE:** Some drives (C:, E:, U:) are auto forbidden from being target drives by default using a 'fixed' parameter inside the .ps1 script; hence edit the .ps1 script to suit your own hard exclusions if any.

3. **Right-click** on your modified `.bat` file and select **"Run as Administrator"**

### Option 2: Direct PowerShell Execution (Run AS Administrator )

```powershell
# This must be Run AS Administrator from a cmd window or Run As

# Basic usage - backup to drives D: and E: with 30% headroom
powershell -NoProfile -ExecutionPolicy Bypass -File "111-Create_system_image_to_drives_RunAs_Admin.ps1" -Target_Drives_List "D: E:" -Headroom_PCT 30 -NoCleanupBeforehand -NoPurgeRestorePoints 

# With 2 types of cleanup and verbose output
powershell -NoProfile -ExecutionPolicy Bypass -File "111-Create_system_image_to_drives_RunAs_Admin.ps1" -Target_Drives_List "D: E: G:" -Headroom_PCT 40 -CleanupBeforehand -PurgeRestorePoints -Verbose
```

## Parameters

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `Target_Drives_List` | String | Space-separated list of target drive letters (e.g., "D: E: G:") |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `Target_Drives_List` | String | **Required** | Space-separated list of target drive letters (e.g., "D: E: G:") |
| `Headroom_PCT` | Integer | **30** | Percentage of extra space to reserve (0-500) |
| `CleanupBeforehand` | Switch | **enabled** | Perform system cleanup before backup |
| `NoCleanupBeforehand` | Switch | - | Skip system cleanup before backup |
| `PurgeRestorePoints` | Switch | - | Delete existing restore points before backup |
| `NoPurgeRestorePoints` | Switch | **enabled** | Keep existing restore points before backup |
| `Verbose` | Switch | **disabled** | Enable detailed logging output |

The **bolded** values are the defaults when no switches are specified.

## Usage Examples

### Example 1: Simple Backup to Two Drives using defaults
```powershell
.\111-Create_system_image_to_drives_RunAs_Admin.ps1 -Target_Drives_List "D: E:" -Headroom_PCT 35
```

### Example 2: Full pre-Imaging Cleanup with Restore Points Purge
```powershell
.\111-Create_system_image_to_drives_RunAs_Admin.ps1 -Target_Drives_List "D: E: G: T:" -Headroom_PCT 40 -CleanupBeforehand -PurgeRestorePoints -Verbose
```

### Example 3: Backup Without Any pre-Imaging Cleanup or Restore Points Purge
```powershell
.\111-Create_system_image_to_drives_RunAs_Admin.ps1 -Target_Drives_List "G: Y:" -NoCleanupBeforehand -NoPurgeRestorePoints
```

## Customizing Batch Files

Edit the batch file variables to suit your needs:

```batch
:: Target drives (modify as needed)
SET "TARGET_DRIVE_LIST=D: E: G: T: I: Y:"

:: Headroom percentage
set "Headroom_PCT=-Headroom_PCT 40"

:: Enable/disable cleanup
set "CleanupBeforehand=-CleanupBeforehand"
REM set "CleanupBeforehand=-NoCleanupBeforehand"

:: Enable/disable restore point purging
set "PurgeRestorePoints=-PurgeRestorePoints"
REM set "PurgeRestorePoints=-NoPurgeRestorePoints"

:: Enable verbose output
REM set "Verbose=-Verbose"
set "Verbose="
```

## Error Handling

The script uses structured exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error |
| 2 | Bad arguments |
| 3 | Precheck failed |
| 4 | Insufficient space |
| 5 | Non-NTFS drive |
| 90-92 | User cancellation |

## Troubleshooting

### Common Issues

**"Not running as Administrator"**
- Right-click batch file and select "Run as Administrator"
- Or run PowerShell as Administrator

**Windows Disk Cleanup (`cleammgr`) takes a long time**
- Yes. Yes it indeed can do. It can even look like it's frozen. Oh well.
- Two small dialogue windows pop up when it is processing each drive - clicking on one pop-up and then on the other (giving each 'focus' in turn) looks to speed it up a bit).

**"Drive not found"**
- Ensure the target drive letters are correct and drives are connected
- Use format "D: E:" (with colons and spaces)

**"Insufficient space"**
- Increase the nominated headroom percentage which will auto-exclude drives without enough free disk space
- Free up space on target drives
- Check space estimate in script output

**"NTFS required"**
- Target drives must be NTFS formatted
- Use Disk Management to check/convert filesystem

### Verbose Output

Add `-Verbose` parameter for detailed logging:
- Powershell auto-generated diagnostics
- Drive validation details
- Space calculations
- Wierd-looking operational details and results
- Backup progress information

## File Locations

- **Script**: `111-Create_system_image_to_drives_RunAs_Admin.ps1` must be in the same folder as the .bat file(s)
- **Batch files**: `*RunAs_Admin.bat`
- **Abort flag**: `%TEMP%\ABORT_BACKUP.flag` is an internal flag to detect cancel requests
- **Windows System Images**: are system image backups, created by Windows, in `WindowsImageBackup` folder on target drives
