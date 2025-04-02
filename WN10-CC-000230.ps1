<#
.SYNOPSIS
This PowerShell script enforces STIG WN10-CC-000230 by preventing users from bypassing Windows Defender SmartScreen prompts for sites in Microsoft Edge.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-CC-000230
SRG             : SRG-OS-000480-GPOS-00227
CCI             : CCI-000366
Vulnerability ID: V-220840
Severity        : Medium

.DESCRIPTION
This script checks and configures the Windows Registry to ensure that users cannot ignore Windows Defender SmartScreen filter warnings for potentially malicious websites in Microsoft Edge.
It sets the 'PreventOverride' DWORD value to 1 under the specified registry path.

This setting corresponds to the Group Policy:
Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Edge >> "Prevent bypassing Windows Defender SmartScreen prompts for sites" = "Enabled"
(Also found under Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft Edge)

Applicability:
 - Applicable to unclassified systems. NA for others.
 - NA for Windows 10 LTSC/B versions as they do not include Microsoft Edge.

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with Administrator privileges.
Example syntax:
PS C:\> .\Set-Stig-WN10-CC-000230.ps1
#>

#Requires -RunAsAdministrator

# Define registry key path and value details
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$valueName = "PreventOverride"
$valueType = "DWORD"
$desiredValue = 1

# Check if the target registry path exists. If not, create it.
if (-not (Test-Path $registryPath)) {
    Write-Host "Registry path '$registryPath' does not exist. Creating..."
    try {
        New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Successfully created registry path '$registryPath'."
    } catch {
        Write-Error "Failed to create registry path '$registryPath'. Error: $($_.Exception.Message)"
        # Exit if path creation fails, as the value cannot be set.
        exit 1
    }
} else {
    Write-Host "Registry path '$registryPath' already exists."
}

# Check the current registry value
$currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

# Compare the current value with the desired value and set if necessary
if ($null -eq $currentValue -or $currentValue.$valueName -ne $desiredValue) {
    Write-Host "Setting registry value '$valueName' at '$registryPath' to '$desiredValue'."
    try {
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type $valueType -Force -ErrorAction Stop
        Write-Host "Successfully set registry value '$valueName' to '$desiredValue'."
    } catch {
        Write-Error "Failed to set registry value '$valueName' at '$registryPath'. Error: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Host "Registry value '$valueName' at '$registryPath' is already configured correctly to '$desiredValue'."
}

Write-Host "STIG WN10-CC-000230 remediation check/apply complete."

# Optional: Exit with code 0 to indicate success for automation purposes
exit 0
