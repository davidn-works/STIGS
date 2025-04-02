<#
.SYNOPSIS
This PowerShell script ensures that the maximum size of the Windows Security event log is configured to 1024000 KB (1 GB) or greater, aligning with STIG WN10-AU-000505.

.DESCRIPTION
This script checks the registry setting for the maximum size of the Security event log.
If the setting does not exist, is not a DWORD, or is set to a value less than 1024000 KB,
it configures the value to 1024000 KB as required by the STIG.
This configuration is applied via the registry path associated with the Group Policy setting:
Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security >> "Specify the maximum log file size (KB)"

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-AU-000505
SRG-ID          : SRG-OS-000341-GPOS-00132
CCI             : CCI-001849
Vulnerability ID: V-220780

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. :

.USAGE
1. Run the script with Administrator privileges.
2. Use the -Verbose switch for detailed output.
Example syntax:
PS C:\Scripts> .\STIG_WN10-AU-000505_Remediation.ps1 -Verbose

.PARAMETER WhatIf
Shows what would happen if the script were run. No changes are made.

.PARAMETER Confirm
Prompts you for confirmation before executing the script.

.INPUTS
None. You cannot pipe objects to this script.

.OUTPUTS
String. Outputs status messages indicating compliance or actions taken.

.LINK
https://www.stigviewer.com/stig/windows_10/2021-08-18/finding/V-220780

.DISCLAIMER
As with any script, test thoroughly in a non-production environment before deploying.
The NA condition (sending logs directly to an audit server) must be verified manually and documented with the ISSO; this script does not check for that condition.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param()

BEGIN {
    Write-Verbose "Starting STIG WN10-AU-000505 script: Security Event Log Size Check & Remediation."

    # Define STIG requirement parameters
    $stigId = "WN10-AU-000505"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
    $valueName = "MaxSize" # Specifies max log size in KB
    $requiredValueKB = 1024000 # Minimum required size in KB (1 GB)
    $valueType = "DWORD"
}

PROCESS {
    Write-Verbose "Checking registry path: $registryPath"

    # Check if the registry path exists
    if (-not (Test-Path -Path $registryPath)) {
        Write-Warning "Registry path '$registryPath' does not exist."
        $needsRemediation = $true
        $currentValue = $null
    } else {
        Write-Verbose "Registry path found."
        # Try to get the current value
        try {
            $registryValue = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction Stop
            $currentValue = $registryValue.$valueName
            $currentType = (Get-ItemProperty -Path $registryPath -Name $valueName).PSObject.Properties[$valueName].TypeName

            Write-Verbose "Found registry value '$valueName'."
            Write-Verbose "Current Value: $currentValue"
            Write-Verbose "Current Type : $currentType"

            # Check if the type is correct and value meets requirement
            if ($currentType -ne $valueType) {
                Write-Warning "Value '$valueName' has incorrect type '$currentType'. Expected '$valueType'."
                $needsRemediation = $true
            } elseif ($currentValue -lt $requiredValueKB) {
                Write-Warning "Current Security log maximum size ($currentValue KB) is less than the required minimum ($requiredValueKB KB)."
                $needsRemediation = $true
            } else {
                Write-Host "[$stigId] Compliant: Security log maximum size is $currentValue KB, which meets or exceeds the minimum requirement of $requiredValueKB KB."
                $needsRemediation = $false
            }
        } catch [Microsoft.PowerShell.Commands.ItemPropertyNotFoundException] {
            Write-Warning "Registry value '$valueName' not found at path '$registryPath'."
            $needsRemediation = $true
            $currentValue = $null
        } catch {
            Write-Error "An unexpected error occurred while checking registry value '$valueName' at '$registryPath': $($_.Exception.Message)"
            # Stop script execution on unexpected errors to prevent incorrect configuration
            throw "Failed to check registry. Error: $($_.Exception.Message)"
        }
    }

    # Apply remediation if needed
    if ($needsRemediation) {
        Write-Host "[$stigId] Remediation required."

        if ($PSCmdlet.ShouldProcess("$registryPath\$valueName", "Set value to $requiredValueKB (Type: $valueType)")) {
            try {
                # Ensure the parent path exists before setting the value
                if (-not (Test-Path -Path $registryPath)) {
                    Write-Verbose "Creating registry path: $registryPath"
                    New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
                }

                Write-Verbose "Setting registry value '$valueName' to '$requiredValueKB' (Type: $valueType) at path '$registryPath'."
                Set-ItemProperty -Path $registryPath -Name $valueName -Value $requiredValueKB -Type $valueType -Force -ErrorAction Stop

                Write-Host "[$stigId] Remediation successful: Set Security log maximum size to $requiredValueKB KB."

            } catch {
                Write-Error "[$stigId] Remediation failed: Could not set registry value '$valueName' at '$registryPath'. Error: $($_.Exception.Message)"
                # Consider re-throwing the error if script failure is desired on remediation failure
                # throw "Remediation failed. Error: $($_.Exception.Message)"
            }
        } else {
             Write-Warning "[$stigId] Remediation skipped due to -WhatIf or user confirmation."
        }
    }
}

END {
    Write-Verbose "Finished STIG WN10-AU-000505 script."
}
