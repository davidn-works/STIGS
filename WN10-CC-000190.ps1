<#
.SYNOPSIS
    This PowerShell script disables Autoplay on Windows 10, implementing STIG rule.

.NOTES
    Author          : David N.
    LinkedIn        : 
    GitHub          : github.com/davidn-works
    Date Created    : 2025-03-10
    Last Modified   : 2025-03-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000190

.TESTED ON
    Date(s) Tested  : A
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run this script with Administrator privileges.
    Example syntax:
    PS C:\> .\Disable-Autoplay.ps1
#>

# Disable Autoplay via Registry
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$RegName = "NoDriveTypeAutoRun"
$RegValue = 255  # 0xFF (Disable on all drives)

# Check if the registry key exists. Create it if it doesn't.
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the registry value (or update it if it exists)
Set-ItemProperty -Path $RegPath -Name $RegName -Value $RegValue -Type DWord -Force

# Disable Autoplay via Group Policy (if applicable)
# This is redundant, but included for completeness and in case GPO takes precedence
gpupdate /force

Write-Host "Autoplay has been disabled."
