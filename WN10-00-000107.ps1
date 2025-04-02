<#
.SYNOPSIS
This PowerShell script ensures that Copilot in Windows is disabled for Windows 10, aligning with STIG ID WN10-00-000107.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-00-000107
SRG             : SRG-OS-000096-GPOS-00050
CCI             : CCI-000382
Vulnerability Id: V-268315
Severity        : Medium

.DESCRIPTION
This script configures the local policy setting "Turn off Windows Copilot" to "Enabled"
by setting the corresponding registry value. This applies to the current user context
as it modifies HKEY_CURRENT_USER.

The STIG requirement maps to:
User Configuration >> Administrative Templates >> Windows Components >> Windows Copilot >> "Turn off Windows Copilot" = "Enabled"

Registry Key: HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot
Value Name:   TurnOffWindowsCopilot
Value Type:   REG_DWORD
Value Data:   1 (Enabled)

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
1. Run this script with the privileges of the user account(s) you want to apply the setting to.
2. Alternatively, deploy via a management tool (like Intune, SCCM) or Group Policy Preferences targeting the user configuration.
3. A logoff/logon or 'gpupdate /force' might be required for the setting to take full effect in the user's session.

Example syntax:
PS C:\Scripts> .\Apply_STIG_WN10-00-000107_Disable_Copilot.ps1
#>

#Requires -Version 5.1

[CmdletBinding()]
param()

Write-Verbose "Starting STIG WN10-00-000107 remediation: Disable Copilot in Windows."

# Define registry path and value details
$registryPath = "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot"
$valueName = "TurnOffWindowsCopilot"
$valueType = "DWORD"
$desiredValueData = 1 # 1 = Enabled (Turn off Copilot)

Write-Verbose "Target Registry Path: $registryPath"
Write-Verbose "Target Value Name : $valueName"
Write-Verbose "Desired Value Data: $desiredValueData (Type: $valueType)"

try {
    # Check if the registry key path exists. If not, create it.
    if (-not (Test-Path -Path $registryPath -ErrorAction SilentlyContinue)) {
        Write-Verbose "Registry path '$registryPath' does not exist. Creating..."
        New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] Created registry path: $registryPath"
    } else {
        Write-Verbose "Registry path '$registryPath' already exists."
    }

    # Get the current value, if it exists
    $currentValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue

    # Check if the value exists and is set correctly
    if ($null -ne $currentValue -and $currentValue.$valueName -eq $desiredValueData) {
        Write-Host "[OK] Setting '$valueName' in '$registryPath' is already compliant (Value: $desiredValueData)."
    } else {
        Write-Verbose "Setting '$valueName' needs configuration."
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $desiredValueData -Type $valueType -Force -ErrorAction Stop
        Write-Host "[+] Applied setting: Set '$valueName' in '$registryPath' to '$desiredValueData'."
        Write-Host "[INFO] A logoff/logon or 'gpupdate /force' may be needed for the setting to fully apply to the current user session."
    }

    Write-Verbose "STIG WN10-00-000107 remediation script finished successfully."

} catch {
    Write-Error "[-] Failed to apply STIG WN10-00-000107."
    Write-Error "Error details: $($_.Exception.Message)"
    # Optionally re-throw the error if used in larger automation
    # throw $_
}

# End of script
