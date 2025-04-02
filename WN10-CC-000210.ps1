<#
.SYNOPSIS
This PowerShell script enforces STIG WN10-CC-000210 by enabling Windows Defender SmartScreen for File Explorer.

.DESCRIPTION
This script configures the necessary registry settings to ensure Windows Defender SmartScreen
is enabled for File Explorer, warning or blocking users from running potentially malicious
programs downloaded from the internet. It adjusts settings based on the detected Windows 10/11 version,
including specific LTSB/LTSC releases as per the STIG requirements.

Requires administrative privileges to modify the HKEY_LOCAL_MACHINE registry hive.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-CC-000210
SRG-ID          : SRG-OS-000095-GPOS-00049
CCI-ID          : CCI-000381
Vulnerability ID: V-220836

.PARAMETER ApplyFix
Switch parameter. If present, the script will apply the registry changes. Otherwise, it only checks the current configuration.

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
To check the current configuration:
PS C:\> .\STIG-WN10-CC-000210_Remediation.ps1

To apply the remediation:
PS C:\> .\STIG-WN10-CC-000210_Remediation.ps1 -ApplyFix

You must run this script as an Administrator to apply the fix.
#>

[CmdletBinding(SupportsShouldProcess = $true)] # Add support for -WhatIf and -Confirm
param(
    [Switch]$ApplyFix
)

# Check for Administrator Privileges if applying the fix
if ($ApplyFix.IsPresent -and (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))) {
    Write-Error "Administrator privileges are required to apply registry changes. Please run the script as Administrator."
    Exit 1 # Exit because changes cannot be made
}

# Define Registry Path
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$enableSmartScreenName = "EnableSmartScreen"
$shellLevelName = "ShellSmartScreenLevel"

# Define target values based on OS Version
$targetEnableValue = $null
$targetShellLevelValue = $null
$osVersionCheckPassed = $true

try {
    # Get OS Version Information
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = [version]$osInfo.Version
    $osCaption = $osInfo.Caption # e.g., "Microsoft Windows 10 Pro"
    $isLTSB = $osCaption -match 'LTSB' # Basic check for LTSB string

    Write-Verbose "Detected OS: $osCaption (Version: $osVersion)"

    # Determine required settings based on OS version
    # Note: Version checks are approximate. 1703 is 10.0.15063.
    # The STIG implies modern versions need both keys, 1607 needs one, 1507 needs one with a different value.
    if ($osVersion -ge [version]'10.0.15063' -and !$isLTSB) { # Modern Windows 10 (v1703+) and Windows 11
        Write-Verbose "Applying settings for modern Windows (v1703+ / Win11)"
        $targetEnableValue = 1
        $targetShellLevelValue = "Block"
    }
    elseif ($osVersion -ge [version]'10.0.14393') { # Includes v1607 LTSB
        Write-Verbose "Applying settings for Windows 10 v1607 LTSB"
        $targetEnableValue = 1
        # ShellSmartScreenLevel is not explicitly required by STIG for 1607
    }
    elseif ($osVersion -ge [version]'10.0.10240') { # Includes v1507 LTSB
        Write-Verbose "Applying settings for Windows 10 v1507 LTSB"
        $targetEnableValue = 2
        # ShellSmartScreenLevel is not explicitly required by STIG for 1507
    }
    else {
        Write-Warning "OS Version $osVersion ($osCaption) is older than supported versions for this STIG check or detection failed. Skipping."
        $osVersionCheckPassed = $false
    }

    if ($osVersionCheckPassed) {
        # Check 1: EnableSmartScreen
        $currentEnableValue = Get-ItemProperty -Path $registryPath -Name $enableSmartScreenName -ErrorAction SilentlyContinue
        $enableValueCompliant = $false
        if ($currentEnableValue -ne $null -and $currentEnableValue.$enableSmartScreenName -eq $targetEnableValue) {
            $enableValueCompliant = $true
        }
        Write-Host "Checking '$enableSmartScreenName'..."
        Write-Host "  Required Value: $targetEnableValue"
        Write-Host "  Current Value : $($currentEnableValue.$enableSmartScreenName | Out-String).Trim()" -ForegroundColor ($null -ne $currentEnableValue ? 'Yellow' : 'Red')
        Write-Host "  Compliant     : $enableValueCompliant" -ForegroundColor ($enableValueCompliant ? 'Green' : 'Red')


        # Check 2: ShellSmartScreenLevel (only if applicable for the detected OS version)
        $shellLevelCompliant = $true # Assume compliant if not applicable
        if ($targetShellLevelValue -ne $null) {
             $currentShellLevelValue = Get-ItemProperty -Path $registryPath -Name $shellLevelName -ErrorAction SilentlyContinue
             $shellLevelCompliant = $false # Reset to false, prove compliance
            if ($currentShellLevelValue -ne $null -and $currentShellLevelValue.$shellLevelName -eq $targetShellLevelValue) {
                $shellLevelCompliant = $true
            }
            Write-Host "Checking '$shellLevelName'..."
            Write-Host "  Required Value: $targetShellLevelValue"
            Write-Host "  Current Value : $($currentShellLevelValue.$shellLevelName | Out-String).Trim()" -ForegroundColor ($null -ne $currentShellLevelValue ? 'Yellow' : 'Red')
            Write-Host "  Compliant     : $shellLevelCompliant" -ForegroundColor ($shellLevelCompliant ? 'Green' : 'Red')
        } else {
             Write-Verbose "'$shellLevelName' check skipped as it's not required for this OS version according to the STIG."
        }


        # Apply Fix if requested and necessary
        if ($ApplyFix.IsPresent) {
            if (-not $enableValueCompliant -or (-not $shellLevelCompliant -and $targetShellLevelValue -ne $null)) {
                 Write-Host "`nApplying Fix for STIG WN10-CC-000210..."

                # Ensure the registry path exists
                if (-not (Test-Path $registryPath)) {
                    if ($PSCmdlet.ShouldProcess($registryPath, "Create Registry Path")) {
                        Write-Host "Creating registry path: $registryPath"
                        New-Item -Path $registryPath -Force | Out-Null
                    }
                }

                # Set EnableSmartScreen value
                if (-not $enableValueCompliant) {
                     if ($PSCmdlet.ShouldProcess("$registryPath\$enableSmartScreenName", "Set Registry Value to $targetEnableValue (DWORD)")) {
                         Write-Host "Setting '$enableSmartScreenName' to '$targetEnableValue' (DWORD)"
                         Set-ItemProperty -Path $registryPath -Name $enableSmartScreenName -Value $targetEnableValue -Type DWord -Force
                     }
                 }

                # Set ShellSmartScreenLevel value (only if applicable)
                if ($targetShellLevelValue -ne $null -and -not $shellLevelCompliant) {
                    if ($PSCmdlet.ShouldProcess("$registryPath\$shellLevelName", "Set Registry Value to '$targetShellLevelValue' (String)")) {
                        Write-Host "Setting '$shellLevelName' to '$targetShellLevelValue' (String)"
                        Set-ItemProperty -Path $registryPath -Name $shellLevelName -Value $targetShellLevelValue -Type String -Force
                    }
                }
                 Write-Host "Remediation applied." -ForegroundColor Green
            } else {
                 Write-Host "`nSystem is already compliant with STIG WN10-CC-000210." -ForegroundColor Green
            }
        } elseif (-not $enableValueCompliant -or (-not $shellLevelCompliant -and $targetShellLevelValue -ne $null)) {
            Write-Warning "System is NOT compliant. Use the -ApplyFix switch to remediate (requires Administrator privileges)."
        } else {
            Write-Host "`nSystem is compliant with STIG WN10-CC-000210." -ForegroundColor Green
        }
    } # End if ($osVersionCheckPassed)

} catch {
    Write-Error "An error occurred: $($_.Exception.Message)"
    Write-Error "Script execution aborted."
}
