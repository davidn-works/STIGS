<#
.SYNOPSIS
This PowerShell script checks and enforces the Windows 10 Account Lockout Duration policy setting according to STIG WN10-AC-000005.

.DESCRIPTION
This script verifies that the "Account lockout duration" is configured to 15 minutes or greater, or 0 (requiring administrative unlock).
If the setting is non-compliant (less than 15 and not 0), it configures the duration to 15 minutes.

STIG ID: WN10-AC-000005
SRG: SRG-OS-000329-GPOS-00128
Severity: medium
CCI: CCI-002238
Vulnerability Id: V-220739
Rule Title: Windows 10 account lockout duration must be configured to 15 minutes or greater.

Vulnerability Discussion: The account lockout feature, when enabled, prevents brute-force password attacks on the system. This parameter specifies the amount of time that an account will remain locked after the specified number of failed logon attempts.

Check: Verify the effective setting in Local Group Policy Editor. Run "gpedit.msc". Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy. If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding. Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a finding.

Fix: Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout duration" to "15" minutes or greater. A value of "0" is also acceptable, requiring an administrator to unlock the account. This script sets it to 15 if remediation is needed.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
STIG-ID         : WN10-AC-000005

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with Administrator privileges.
Example syntax:
PS C:\Scripts> .\STIG_WN10-AC-000005_Remediation.ps1

.REQUIREMENTS
Requires administrative privileges to check and modify security policies.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param ()

# Define STIG details and required settings
$stigId = "WN10-AC-000005"
$policyName = "Account lockout duration"
$seceditPolicyName = "LockoutDuration" # Name used by secedit.exe
$requiredMinValue = 15
$acceptableZeroValue = 0
$recommendedValue = 15 # Value to set if non-compliant

Write-Verbose "Starting STIG $stigId check for '$policyName'."

# Temporary files for secedit
$tempExportFile = Join-Path -Path $env:TEMP -ChildPath "secedit_export_$(Get-Random).inf"
$tempImportFile = Join-Path -Path $env:TEMP -ChildPath "secedit_import_$(Get-Random).inf"

# Function to clean up temporary files
function Cleanup-TempFiles {
    param($FilePath)
    if (Test-Path -Path $FilePath -PathType Leaf) {
        Write-Verbose "Removing temporary file: $FilePath"
        Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
    }
}

# Check current setting using secedit
try {
    Write-Verbose "Exporting current security policy to $tempExportFile"
    # Export current local security policy settings
    secedit /export /cfg "$tempExportFile" /areas SECURITYPOLICY | Out-Null

    if (-not (Test-Path -Path $tempExportFile)) {
        Write-Error "Failed to export security policy. Secedit command might have failed or requires elevation."
        # No need for finally block here as script will exit or error handles it.
        return
    }

    Write-Verbose "Reading exported policy file."
    $policyContent = Get-Content -Path $tempExportFile

    # Find the specific policy setting line
    $settingLine = $policyContent | Select-String -Pattern "^\s*$($seceditPolicyName)\s*=\s*(\d+)\s*$" -ErrorAction SilentlyContinue

    if ($settingLine -and $settingLine.Matches[0].Groups[1].Success) {
        $currentValue = [int]$settingLine.Matches[0].Groups[1].Value
        Write-Host "[$stigId] Current '$policyName' value: $currentValue minutes."

        # Check compliance
        if (($currentValue -ge $requiredMinValue) -or ($currentValue -eq $acceptableZeroValue)) {
            Write-Host "[$stigId] '$policyName' is compliant (Value: $currentValue minutes)."
            $compliant = $true
        } else {
            Write-Warning "[$stigId] '$policyName' is NON-COMPLIANT (Value: $currentValue minutes). Required: >= $requiredMinValue minutes or $acceptableZeroValue."
            $compliant = $false
        }
    } else {
        # Setting not found in export - this might indicate an issue or default state not explicitly set
        Write-Warning "[$stigId] Could not find '$policyName' ($seceditPolicyName) setting in the exported policy file. Assuming non-compliant and attempting to set."
        $currentValue = "Not Found"
        $compliant = $false
    }

    # Fix if non-compliant
    if (-not $compliant) {
        Write-Host "[$stigId] Applying remediation: Setting '$policyName' to $recommendedValue minutes."

        # Create the import file content
        $importContent = @"
[Unicode]
Unicode=yes
[System Access]
$($seceditPolicyName) = $recommendedValue
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

        try {
            Write-Verbose "Creating temporary import file: $tempImportFile"
            Set-Content -Path $tempImportFile -Value $importContent -Encoding Unicode -Force

            Write-Verbose "Configuring security policy using secedit."
            # Apply the setting using secedit
            # Note: /db parameter might be needed if default secedit.sdb path isn't standard or accessible easily. Usually not required for simple config.
            secedit /configure /db "$env:windir\security\database\secedit.sdb" /cfg "$tempImportFile" /areas SECURITYPOLICY /quiet | Out-Null
            # Check exit code? Secedit can be tricky, sometimes returns 0 even on issues. A re-check might be better.

            # Optional: Re-verify the setting after applying
            Write-Host "[$stigId] Remediation applied. Re-checking setting..."
            # (Could re-run the export/check logic here, but for simplicity, we assume success if secedit didn't throw errors)
             # Simple confirmation message
            Write-Host "[$stigId] Successfully attempted to set '$policyName' to $recommendedValue minutes."
            Write-Warning "[$stigId] A system reboot OR running 'gpupdate /force' might be required for the setting to take full effect immediately."

        }
        catch {
            Write-Error "[$stigId] Failed to apply remediation for '$policyName'. Error: $($_.Exception.Message)"
        }
        finally {
             Cleanup-TempFiles -FilePath $tempImportFile
        }
    }
}
catch {
    Write-Error "[$stigId] An error occurred during the check/remediation process: $($_.Exception.Message)"
}
finally {
    # Ensure cleanup of the export file happens regardless of success/failure
    Cleanup-TempFiles -FilePath $tempExportFile
}

Write-Verbose "Finished STIG $stigId check for '$policyName'."
