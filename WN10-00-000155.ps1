<#
.SYNOPSIS
This PowerShell script ensures that the Windows PowerShell 2.0 feature is disabled on the system, aligning with STIG WN10-00-000155.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-00-000155
Vulnerability Id: V-220728
SRG             : SRG-OS-000095-GPOS-00049
CCI             : CCI-000381

.DESCRIPTION
Windows PowerShell 5.0 added advanced logging features. Disabling the Windows PowerShell 2.0
mitigates against a downgrade attack that evades the Windows PowerShell 5.0 script block logging feature.
This script checks if the PowerShell v2 features ('MicrosoftWindowsPowerShellV2' and
'MicrosoftWindowsPowerShellV2Root') are enabled and disables them if necessary.

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
1. Save the script to a .ps1 file (e.g., Disable-PSv2_WN10-00-000155.ps1).
2. Open PowerShell as an Administrator.
3. Run the script: .\Disable-PSv2_WN10-00-000155.ps1
The script will check the status and attempt remediation if needed. A reboot may be required.

Example syntax:
PS C:\Scripts> .\Disable-PSv2_WN10-00-000155.ps1
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

begin {
    Write-Host "Starting STIG WN10-00-000155 Check/Remediation: Disable PowerShell v2..."
    $ErrorActionPreference = 'Stop' # Exit script on non-terminating errors

    # Feature names to check/disable
    $featureNameRoot = "MicrosoftWindowsPowerShellV2Root"
    $featureNameEngine = "MicrosoftWindowsPowerShellV2" # Check only, Root disables both
    $remediationNeeded = $false
    $rebootRequired = $false
}

process {
    try {
        Write-Host "Checking status of PowerShell v2 features..."

        # Check the root feature first as it's the primary target for disable action
        $featureRoot = Get-WindowsOptionalFeature -Online -FeatureName $featureNameRoot -ErrorAction SilentlyContinue
        # Check the engine feature for completeness of the check phase
        $featureEngine = Get-WindowsOptionalFeature -Online -FeatureName $featureNameEngine -ErrorAction SilentlyContinue

        if ($null -eq $featureRoot -and $null -eq $featureEngine) {
             Write-Host "WARN: Could not retrieve status for PowerShell v2 features. They might not be available on this OS version or an error occurred."
             # Assuming non-compliant or unable to verify if features aren't found explicitly disabled
             # Depending on policy, you might treat this differently. Here, we'll assume it's okay if not found.
             Write-Host "INFO: Assuming compliant as features were not found."
             $remediationNeeded = $false
        } else {
            # Check if either feature is enabled
            if (($featureRoot -ne $null -and $featureRoot.State -eq 'Enabled') -or ($featureEngine -ne $null -and $featureEngine.State -eq 'Enabled')) {
                Write-Host "NON-COMPLIANT: PowerShell v2 feature(s) are enabled."
                Write-Host "  $($featureNameRoot): $($featureRoot.State)"
                Write-Host "  $($featureNameEngine): $($featureEngine.State)"
                $remediationNeeded = $true
            } else {
                Write-Host "COMPLIANT: PowerShell v2 features are disabled or not present."
                Write-Host "  $($featureNameRoot): $($featureRoot.State)"
                Write-Host "  $($featureNameEngine): $($featureEngine.State)"
                $remediationNeeded = $false
            }
        }

        # Remediation
        if ($remediationNeeded) {
            Write-Host "Attempting remediation: Disabling '$($featureNameRoot)'..."
            # Disabling the Root feature should disable both Root and Engine
            $disableResult = Disable-WindowsOptionalFeature -Online -FeatureName $featureNameRoot -NoRestart -ErrorAction Stop
            Write-Host "Remediation command executed."

            # Check if a reboot is required
            if ($disableResult.RestartNeeded) {
                $rebootRequired = $true
                Write-Host "WARNING: A system reboot is required to complete the disabling of PowerShell v2." -ForegroundColor Yellow
            } else {
                 Write-Host "PowerShell v2 feature '$($featureNameRoot)' disabled successfully (pending potential reboot if previously indicated)." -ForegroundColor Green
            }

            # Optional: Verify after remediation attempt (before potential reboot)
            Write-Host "Verifying status post-remediation attempt..."
            $featureRootPost = Get-WindowsOptionalFeature -Online -FeatureName $featureNameRoot
            $featureEnginePost = Get-WindowsOptionalFeature -Online -FeatureName $featureNameEngine
            if ($featureRootPost.State -ne 'Enabled' -and $featureEnginePost.State -ne 'Enabled') {
                 Write-Host "VERIFIED: PowerShell v2 features are now disabled (State: $($featureRootPost.State), $($featureEnginePost.State))." -ForegroundColor Green
            } else {
                 Write-Host "VERIFICATION FAILED: PowerShell v2 features still report as enabled (State: $($featureRootPost.State), $($featureEnginePost.State)). Manual check or reboot might be needed." -ForegroundColor Yellow
            }

        } else {
            Write-Host "No remediation required."
        }

    } catch {
        Write-Error "An error occurred during the script execution: $($_.Exception.Message)"
        # Exit with a non-zero code to indicate failure for automation tools
        exit 1
    }
}

end {
    Write-Host "Finished STIG WN10-00-000155 Check/Remediation."
    if ($rebootRequired) {
        Write-Host "REMINDER: A system reboot is required for changes to fully apply." -ForegroundColor Yellow
    }
    # Exit with 0 for success
    exit 0
}
