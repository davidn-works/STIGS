<#
.SYNOPSIS
This PowerShell script ensures that Solicited Remote Assistance is disabled, aligning with STIG WN10-CC-000155.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-CC-000155
SRG-ID          : SRG-OS-000138-GPOS-00069
CCI-ID          : CCI-001090
Vulnerability ID: V-220823

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with Administrator privileges to check and apply the required registry setting.
Example syntax:
PS C:\Scripts> .\Apply-STIG-WN10-CC-000155.ps1
#>

#Requires -RunAsAdministrator

# Define STIG information
$StigID = "WN10-CC-000155"
$StigTitle = "Solicited Remote Assistance must not be allowed"

# Define Registry Information
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$RegValueName = "fAllowToGetHelp"
$DesiredValue = 0
$ValueType = "DWord"

Write-Host "Starting check for STIG ID: $StigID ($StigTitle)..."

# Check if the registry path exists. If not, the setting is not configured via policy (or needs creation).
if (-not (Test-Path -Path $RegPath)) {
    Write-Host "Registry path '$RegPath' does not exist. Creating path and setting value..."
    try {
        # Create the registry path
        New-Item -Path $RegPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Successfully created registry path: $RegPath"

        # Set the desired registry value
        New-ItemProperty -Path $RegPath -Name $RegValueName -Value $DesiredValue -PropertyType $ValueType -Force -ErrorAction Stop | Out-Null
        Write-Host "Successfully set '$RegValueName' to '$DesiredValue' (DWORD) in '$RegPath'."
        Write-Host "STIG Check: $StigID - PASSED (Remediated)"
    }
    catch {
        Write-Error "Failed to create path or set registry value for STIG $StigID. Error: $($_.Exception.Message)"
        Write-Host "STIG Check: $StigID - FAILED (Remediation Error)"
        Exit 1 # Indicate failure
    }
}
else {
    # Path exists, check the value
    Write-Host "Registry path '$RegPath' exists. Checking value '$RegValueName'..."
    $CurrentValue = Get-ItemProperty -Path $RegPath -Name $RegValueName -ErrorAction SilentlyContinue

    if ($CurrentValue -ne $null -and $CurrentValue.$RegValueName -eq $DesiredValue) {
        Write-Host "'$RegValueName' is already set to the required value ($DesiredValue)."
        Write-Host "STIG Check: $StigID - PASSED"
    }
    else {
        # Value is missing or incorrect, apply the fix
        if ($CurrentValue -eq $null) {
            Write-Host "'$RegValueName' does not exist. Creating and setting value..."
        } else {
            Write-Host "'$RegValueName' is set to '$($CurrentValue.$RegValueName)', which is incorrect. Setting to '$DesiredValue'..."
        }

        try {
            Set-ItemProperty -Path $RegPath -Name $RegValueName -Value $DesiredValue -Type $ValueType -Force -ErrorAction Stop | Out-Null
            Write-Host "Successfully set '$RegValueName' to '$DesiredValue' (DWORD) in '$RegPath'."
            Write-Host "STIG Check: $StigID - PASSED (Remediated)"
        }
        catch {
            Write-Error "Failed to set registry value for STIG $StigID. Error: $($_.Exception.Message)"
            Write-Host "STIG Check: $StigID - FAILED (Remediation Error)"
            Exit 1 # Indicate failure
        }
    }
}

Write-Host "Finished check for STIG ID: $StigID."
Exit 0 # Indicate success
