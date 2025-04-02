<#
.SYNOPSIS
This PowerShell script enforces STIG WN10-CC-000005 by disabling camera access from the lock screen.

.DESCRIPTION
This script configures the system policy to prevent enabling the lock screen camera by setting the appropriate registry value.
This aligns with STIG ID WN10-CC-000005 (V-220792), which requires camera access from the lock screen to be disabled.
If the device does not have a camera, this setting is technically Not Applicable (NA) for checks, but applying the setting ensures compliance if a camera is added later and causes no harm on systems without one.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-CC-000005
SRG             : SRG-OS-000095-GPOS-00049
CCI             : CCI-000381
Vulnerability ID: V-220792

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with elevated privileges (Administrator).
Example syntax:
PS C:\Scripts> .\Remediate-WN10-CC-000005.ps1
#>

#Requires -RunAsAdministrator

param()

# Define STIG details
$stigId = "WN10-CC-000005"
$stigTitle = "Camera access from the lock screen must be disabled"

# Define registry key path, value name, value data, and value type
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$valueName    = "NoLockScreenCamera"
$valueData    = 1
$valueType    = "DWORD"

# Function to check and apply the registry setting
function Set-StigRegistryValue {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        $Value,
        [Parameter(Mandatory=$true)]
        [string]$Type
    )

    try {
        Write-Verbose "Checking registry path: $Path"
        # Ensure the registry path exists, create if it doesn't
        if (-not (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
            Write-Verbose "Registry path does not exist. Creating path: $Path"
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        # Get the current value, if it exists
        $currentValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue

        # Compare current value with desired value
        if ($currentValue -ne $null -and $currentValue.$Name -eq $Value) {
            Write-Host "[$stigId] Setting '$Name' already configured correctly in '$Path'."
        } else {
            Write-Host "[$stigId] Setting '$Name' in '$Path'. Setting value to '$Value'."
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
            Write-Host "[$stigId] Successfully set '$Name' to '$Value'."
        }
    } catch {
        Write-Error "[$stigId] Failed to set registry value '$Name' at path '$Path'. Error: $($_.Exception.Message)"
        # Exit the script with a non-zero exit code to indicate failure
        exit 1
    }
}

# Main script execution
Write-Host "Starting remediation for STIG $stigId: $stigTitle"

# Apply the registry setting
Set-StigRegistryValue -Path $registryPath -Name $valueName -Value $valueData -Type $valueType

Write-Host "Finished remediation for STIG $stigId."

# Optional: Exit with 0 to indicate success
exit 0
