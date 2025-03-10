<#
.SYNOPSIS
This PowerShell script ensures that User Account Control (UAC) is configured to detect application installations and prompt for elevation.

.NOTES
Author          : David N.
LinkedIn        : linkedin.com/in/joshmadakor/
GitHub          : github.com/joshmadakor1
Date Created    : 2025-03-09
Last Modified   : 2025-03-09
Version         : 1.1
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-SO-000260

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with elevated (administrator) privileges.  The script will check the current setting and, if necessary, modify the registry to enable installer detection. A reboot may be required for the changes to take full effect.

Example syntax:
PS C:> .__remediation_template(STIG-ID-WN10-SO-000260).ps1

.DESCRIPTION
This script implements the STIG requirement WN10-SO-000260, which mandates that UAC be set to detect application
installations and prompt the user for elevation.  It achieves this by checking and, if needed, modifying the
'EnableInstallerDetection' registry value.

#>

# --- Check Section ---

$registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName = "EnableInstallerDetection"
$expectedValue = 1
$stigID = "WN10-SO-000260"

try {
    $currentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction Stop).$valueName
}
catch [System.Management.Automation.ItemNotFoundException] {
    Write-Warning "Registry key '$valueName' not found.  This is a finding."
    $currentValue = $null  # Set to null to ensure the fix is applied.
}
catch {
    Write-Error "Error accessing registry: $($_.Exception.Message)"
    exit 1 # Exit with an error code
}


if ($currentValue -eq $expectedValue) {
    Write-Host "STIG $stigID is compliant.  Value '$valueName' is set to '$currentValue'."
    exit 0 # Exit with a success code
}
else {
    Write-Warning "STIG $stigID is NOT compliant.  Value '$valueName' is currently set to '$currentValue'. Expected value is '$expectedValue'."


    # --- Fix Section ---
    Write-Host "Attempting to remediate STIG $stigID..."

    try {
        # -Force will create the key if it doesn't exist
        Set-ItemProperty -Path $registryPath -Name $valueName -Value $expectedValue -Type DWORD -Force -ErrorAction Stop
        Write-Host "Successfully set registry value '$valueName' to '$expectedValue'."

        #Check Again to confirm change
         $newcurrentValue = (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction Stop).$valueName
         if ($newcurrentValue -eq $expectedValue){
            Write-Host "STIG $stigID remediation Successful."
             Write-Warning "A reboot may be required for the changes to take full effect."
            exit 0 # Exit with success after remediation.
         }
         else{
            Write-Error "STIG $stigID remediation FAILED.  Value could not be set"
            exit 1
         }
    }
    catch {
        Write-Error "Error setting registry value: $($_.Exception.Message)"
        exit 1
    }
}
