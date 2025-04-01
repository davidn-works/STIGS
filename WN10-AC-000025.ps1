#Requires -RunAsAdministrator
<#
.SYNOPSIS
This PowerShell script ensures that the maximum password age is configured to 60 days or less (but not 0).

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-AC-000025
SRG-ID          : SRG-OS-000076-GPOS-00044
CCI-ID          : CCI-004066, CCI-000199
Vulnerability Id: V-220743
Severity        : medium

.DESCRIPTION
This script checks and configures the local security policy for the maximum password age.
The STIG requirement WN10-AC-000025 mandates that the maximum password age must be 60 days or less,
and must not be set to 0 (never expires). This script verifies the current setting and, if non-compliant,
configures it to 60 days.

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
1. Save the script as a .ps1 file (e.g., Apply-Stig-WN10-AC-000025.ps1).
2. Open PowerShell as an Administrator.
3. Run the script: .\Apply-Stig-WN10-AC-000025.ps1
The script will check the setting and apply the fix if necessary.

Example syntax:
PS C:\Scripts> .\Apply-Stig-WN10-AC-000025.ps1
#>

# Define the STIG ID and desired value
$StigId = "WN10-AC-000025"
$DesiredMaxPasswordAge = 60 # Days. Must be <= 60 and > 0.

Write-Host "Starting check for STIG ID: $StigId - Maximum password age"

# Check current setting using 'net accounts'
Write-Host "Checking current maximum password age..."
try {
    $netAccountsOutput = net accounts
    $currentMaxAgeLine = $netAccountsOutput | Select-String -Pattern "Maximum password age \(days\):"
    # Use regex to extract the number or 'NEVER'
    if ($currentMaxAgeLine -match 'Maximum password age \(days\):\s*(\d+|NEVER)') {
        $currentValueStr = $Matches[1]
        if ($currentValueStr -eq 'NEVER') {
            $currentMaxAge = 0 # Treat 'NEVER' as 0 for comparison
        } else {
            $currentMaxAge = [int]$currentValueStr
        }
        Write-Host "Current maximum password age: $currentValueStr days"

        # Evaluate compliance
        if ($currentMaxAge -gt 0 -and $currentMaxAge -le $DesiredMaxPasswordAge) {
            Write-Host "[OK] Maximum password age ($currentMaxAge days) is compliant (<= $DesiredMaxPasswordAge days and not 0)."
        } else {
            Write-Warning "[FINDING] Maximum password age ($currentValueStr days) is NOT compliant. It must be between 1 and $DesiredMaxPasswordAge days."
            Write-Host "Applying fix: Setting maximum password age to $DesiredMaxPasswordAge days..."

            # Apply the fix using 'net accounts'
            try {
                net accounts /maxpwage:$DesiredMaxPasswordAge | Out-Null
                # Verify the change
                $netAccountsOutputAfter = net accounts
                $newMaxAgeLine = $netAccountsOutputAfter | Select-String -Pattern "Maximum password age \(days\):"
                 if ($newMaxAgeLine -match 'Maximum password age \(days\):\s*(\d+)') {
                     $newMaxAge = [int]$Matches[1]
                     if ($newMaxAge -eq $DesiredMaxPasswordAge) {
                         Write-Host "[FIXED] Successfully set maximum password age to $newMaxAge days."
                     } else {
                         Write-Error "[FAIL] Failed to verify the change. Current value found: $newMaxAge"
                     }
                 } else {
                     Write-Error "[FAIL] Could not verify the setting after attempting the fix."
                 }
            } catch {
                Write-Error "[FAIL] Error applying fix for STIG $StigId. Error: $($_.Exception.Message)"
            }
        }
    } else {
        Write-Error "[FAIL] Could not parse 'net accounts' output to determine the current maximum password age."
    }
} catch {
    Write-Error "[FAIL] Error running 'net accounts' command. Error: $($_.Exception.Message)"
}

Write-Host "Finished check for STIG ID: $StigId"
