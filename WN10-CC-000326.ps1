<#
.SYNOPSIS
    This STIG requires enabling detailed logging of PowerShell script execution. This is crucial for auditing and incident response, as it allows you to see exactly what commands and scripts were run. It aids in detecting malicious PowerShell activity.

.NOTES
    Author          : David N.
    LinkedIn        : linkedin.com/in
    GitHub          : github.com/davidn-works
    Date Created    : 2025-03-07  
    Last Modified   : 2025-03-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-CC-000326

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Open Powershell ISE as an administrator and paste or run the following code below to remediate the STIG.
#>

# Set the registry key to enable Script Block Logging
$keyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $keyPath)) {
    New-Item -Path $keyPath -Force | Out-Null
}
Set-ItemProperty -Path $keyPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
Write-Host "PowerShell Script Block Logging Enabled."
