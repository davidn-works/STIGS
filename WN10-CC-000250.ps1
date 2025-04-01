<#
.SYNOPSIS
This PowerShell script ensures that the Windows Defender SmartScreen filter for Microsoft Edge is enabled via the required registry setting.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-CC-000250
SRG-ID          : SRG-OS-000480-GPOS-00227
CCI-ID          : CCI-000366
Vulnerability ID: V-220844

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with Administrator privileges.
Example syntax:
PS C:\Scripts> .\STIG-WN10-CC-000250_Remediation.ps1
PS C:\Scripts> .\STIG-WN10-CC-000250_Remediation.ps1 -Verbose
#>

[CmdletBinding()]
param()

#Requires -RunAsAdministrator

# Check for Administrator Privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges to modify HKLM registry keys. Please run it as Administrator."
    # Optional: Uncomment the next line to stop the script if not running as admin
    # return
    # Optional: Attempt to relaunch as admin (may trigger UAC)
    # Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    # exit # Exit the non-elevated instance
}

# STIG Details
$StigId = "WN10-CC-000250"
$Description = "Enable Windows Defender SmartScreen for Microsoft Edge"

# Registry Configuration
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter"
$valueName = "EnabledV9"
$desiredValue = 1
$valueType = "DWord"

Write-Host "Starting STIG $StigId remediation: $Description"

# Check if the registry path exists. If not, create it.
Write-Verbose "Checking registry path: $registryPath"
if (-not (Test-Path -Path $registryPath)) {
    Write-Verbose "Registry path does not exist. Creating path: $registryPath"
    try {
        New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Successfully created registry path: $registryPath"
    } catch {
        Write-Error "Failed to create registry path '$registryPath'. Error: $($_.Exception.Message)"
        # Exit the script if path creation fails, as setting the value will also fail.
        return
    }
} else {
    Write-Verbose "Registry path already exists."
}

# Check the current value of the registry setting
Write-Verbose "Checking registry value '$valueName' at path '$registryPath'"
$currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

# If the value doesn't exist or is not set correctly, configure it.
if ($null -eq $currentValue -or $currentValue.$valueName -ne $desiredValue) {
    if ($null -eq $currentValue) {
        Write-Host "Registry value '$valueName' does not exist. Setting value to '$desiredValue'."
    } else {
        Write-Host "Registry value '$valueName' is set to '$($currentValue.$valueName)'. Correcting to '$desiredValue'."
    }
    try {
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValue -Type $valueType -Force -ErrorAction Stop
        Write-Host "Successfully set registry value '$valueName' to '$desiredValue'."
    } catch {
        Write-Error "Failed to set registry value '$valueName' at '$registryPath'. Error: $($_.Exception.Message)"
        return
    }
} else {
    Write-Host "Registry value '$valueName' at '$registryPath' is already compliant (Value: $desiredValue)."
}

Write-Host "Finished STIG $StigId remediation."
