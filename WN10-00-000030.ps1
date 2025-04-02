<#
.SYNOPSIS
This PowerShell script checks if all fixed drives (OS and data) are encrypted using BitLocker, aligning with STIG WN10-00-000030. It reports compliance status and provides guidance if drives are found unencrypted.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-00-000030
Vulnerability Id: V-220702
CCI             : CCI-001199, CCI-002475, CCI-002476
SRG             : SRG-OS-000185-GPOS-00079

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
1. Run the script with Administrator privileges.
2. The script will output the BitLocker status for each fixed drive.
3. It will conclude with an overall compliance status message.
4. If non-compliant, it will list the drives needing encryption and provide basic guidance.

Example syntax:
PS C:\Scripts> .\Check-Stig-WN10-00-000030.ps1 -Verbose
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Write-Verbose "Starting STIG WN10-00-000030 Check: BitLocker Encryption for All Fixed Disks"

#region STIG Metadata
$STIGID = "WN10-00-000030"
$Severity = "High"
$RuleTitle = "Windows 10 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest."
#endregion

#region Script Variables
$isCompliant = $true
$nonCompliantDrives = [System.Collections.Generic.List[string]]::new()
#endregion

#region VDI/AVD/Alternate Encryption Notes
Write-Host "*** IMPORTANT NOTES ***" -ForegroundColor Yellow
Write-Host "- This check may be Not Applicable (NA) for certain VDI/AVD configurations (e.g., non-persistent desktops, no data at rest)." -ForegroundColor Yellow
Write-Host "- Manual verification is required to confirm NA status for VDI/AVD." -ForegroundColor Yellow
Write-Host "- An approved alternate full disk encryption tool may be used instead of BitLocker. This script only checks for BitLocker." -ForegroundColor Yellow
Write-Host "- Manual verification is required if an alternate tool is used." -ForegroundColor Yellow
Write-Host "*********************"
#endregion

#region Check Logic
Write-Verbose "Identifying fixed drives..."
$fixedVolumes = Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter}

if ($null -eq $fixedVolumes) {
    Write-Warning "No fixed drives with drive letters found. Cannot perform BitLocker check."
    # Consider if this state is compliant or requires investigation based on system role
    # For this script, we'll assume it's unusual and potentially non-compliant or requires manual check.
    $isCompliant = $false
    Write-Host "Compliance Status: Non-Compliant (No fixed drives found/accessible)" -ForegroundColor Red
} else {
    Write-Verbose "Found $($fixedVolumes.Count) fixed drive(s) with drive letters: $($fixedVolumes.DriveLetter -join ', ')"

    foreach ($volume in $fixedVolumes) {
        $driveLetter = $volume.DriveLetter
        Write-Verbose "Checking BitLocker status for drive $($driveLetter):"

        try {
            # Get BitLocker status for the specific volume
            # Use -ErrorAction Stop to ensure the catch block executes on cmdlet errors
            $bitlockerStatus = Get-BitLockerVolume -MountPoint "$($driveLetter):" -ErrorAction Stop

            # Check the VolumeStatus property
            # Possible statuses include: FullyDecrypted, FullyEncrypted, EncryptionInProgress, DecryptionInProgress, EncryptionSuspended, DecryptionSuspended
            # For this STIG, we primarily care if it's NOT encrypted or encryption isn't actively protecting.
            # 'FullyEncrypted' is the desired compliant state.
            # We treat 'EncryptionInProgress' as potentially compliant but note it. Other states are non-compliant.
            Write-Verbose " -> Drive $($driveLetter): Volume Status: $($bitlockerStatus.VolumeStatus), Protection Status: $($bitlockerStatus.ProtectionStatus)"

            if ($bitlockerStatus.VolumeStatus -ne 'FullyEncrypted') {
                 # Also check if protection is ON. If suspended, it's not effectively protecting data at rest per intent.
                 # ProtectionStatus: Off, On, Unknown
                 if ($bitlockerStatus.ProtectionStatus -ne 'On') {
                    Write-Warning " -> Drive $($driveLetter): is not fully encrypted or protection is OFF/Suspended (VolumeStatus: $($bitlockerStatus.VolumeStatus), ProtectionStatus: $($bitlockerStatus.ProtectionStatus))."
                    $isCompliant = $false
                    $nonCompliantDrives.Add("$($driveLetter): (Status: $($bitlockerStatus.VolumeStatus), Protection: $($bitlockerStatus.ProtectionStatus))")
                 } else {
                     # If it's encrypting, it's heading towards compliance, but technically not there yet.
                     # Depending on interpretation, could be a finding until complete. Let's flag it but maybe less severely.
                     Write-Warning " -> Drive $($driveLetter): Encryption is in progress or state is not 'FullyEncrypted' but protection is On (VolumeStatus: $($bitlockerStatus.VolumeStatus)). Verify completion."
                     # Decide if this intermediate state counts as non-compliant for the script's purpose.
                     # For strictness based on "is encrypted", we'll count it.
                     $isCompliant = $false
                     $nonCompliantDrives.Add("$($driveLetter): (Status: $($bitlockerStatus.VolumeStatus), Protection: $($bitlockerStatus.ProtectionStatus) - Needs Verification/Completion)")
                 }
            } else {
                # Status is FullyEncrypted, now check ProtectionStatus
                 if ($bitlockerStatus.ProtectionStatus -ne 'On') {
                    Write-Warning " -> Drive $($driveLetter): is encrypted but protection is OFF/Suspended (ProtectionStatus: $($bitlockerStatus.ProtectionStatus))."
                    $isCompliant = $false
                    $nonCompliantDrives.Add("$($driveLetter): (Status: $($bitlockerStatus.VolumeStatus), Protection: $($bitlockerStatus.ProtectionStatus) - Protection Suspended)")
                 } else {
                    Write-Host " -> Drive $($driveLetter): is Fully Encrypted and Protection is On." -ForegroundColor Green
                 }
            }
        } catch {
            # Handle errors like BitLocker service not running, volume not supporting BitLocker, etc.
            Write-Error " -> Failed to get BitLocker status for drive $($driveLetter):. Error: $($_.Exception.Message)"
            $isCompliant = $false
            $nonCompliantDrives.Add("$($driveLetter): (Error retrieving status)")
        }
    } # End foreach volume
} # End else ($null -eq $fixedVolumes)
#endregion

#region Compliance Reporting and Remediation Guidance
Write-Host "`n---------------------------------"
Write-Host "STIG ID     : $STIGID"
Write-Host "Rule Title  : $RuleTitle"
Write-Host "Severity    : $Severity"
Write-Host "---------------------------------"

if ($isCompliant) {
    Write-Host "Compliance Status: Compliant" -ForegroundColor Green
    Write-Host "All fixed drives checked are encrypted using BitLocker with protection enabled."
} else {
    Write-Host "Compliance Status: Non-Compliant" -ForegroundColor Red
    Write-Host "One or more fixed drives are not encrypted with BitLocker or protection is not active."
    Write-Host "Drives requiring attention:" -ForegroundColor Yellow
    foreach ($drive in $nonCompliantDrives) {
        Write-Host "- $drive" -ForegroundColor Yellow
    }

    Write-Host "`n--- Remediation Guidance ---" -ForegroundColor Cyan
    Write-Host "To remediate, enable BitLocker on the non-compliant drives."
    Write-Host "1. Open Control Panel -> 'BitLocker Drive Encryption'."
    Write-Host "2. Click 'Turn on BitLocker' for the affected drives."
    Write-Host "3. Follow the wizard to configure protectors (e.g., TPM, PIN, Password, Recovery Key) according to site policy."
    Write-Host "4. Ensure appropriate recovery key backup procedures are followed (e.g., save to AD DS, file, USB, print)."
    Write-Host "Alternatively, use PowerShell (Run as Administrator):" -ForegroundColor Cyan
    Write-Host "Example (TPM only for OS drive C:): Enable-BitLocker -MountPoint 'C:' -EncryptionMethod Aes256 -TpmProtector" -ForegroundColor Cyan
    Write-Host "Example (Password for data drive E:): Enable-BitLocker -MountPoint 'E:' -EncryptionMethod Aes256 -PasswordProtector" -ForegroundColor Cyan
    Write-Host "Consult your organization's specific policies for required protectors and encryption methods (e.g., XtsAes128, XtsAes256)." -ForegroundColor Cyan
    Write-Host "NOTE: Enabling BitLocker encryption can take a significant amount of time." -ForegroundColor Cyan
    Write-Host "Ensure the pre-boot authentication requirements (WN10-00-000031 and WN10-00-000032) are also met." -ForegroundColor Cyan
}

Write-Verbose "Finished STIG WN10-00-000030 Check."
#endregion
