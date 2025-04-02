<#
.SYNOPSIS
This PowerShell script ensures that the minimum password age is configured to at least 1 day, aligning with STIG ID WN10-AC-000030.

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-AC-000030
SRG             : SRG-OS-000075-GPOS-00043
CCI             : CCI-004066, CCI-000198
Vulnerability Id: V-220744
Severity        : medium

.DESCRIPTION
This script checks and enforces the Windows security setting "Minimum password age".
The STIG requirement mandates this value be set to at least 1 day.
Permitting passwords to be changed in immediate succession within the same day allows users
to cycle passwords through their history database. This enables users to effectively negate
the purpose of mandating periodic password changes.

The script uses secedit.exe to export the current security policy, checks the value,
and if non-compliant, creates a temporary policy file to configure the setting correctly
and applies it using secedit.exe.

Requires administrative privileges to run.

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
1. Save the script as a .ps1 file (e.g., Apply-STIG-WN10-AC-000030.ps1).
2. Open PowerShell as an Administrator.
3. Run the script:
   PS C:\Scripts> .\Apply-STIG-WN10-AC-000030.ps1

Output will indicate whether the setting is compliant or if remediation was applied.
#>

#Requires -RunAsAdministrator

# Define STIG details and required setting
$stigId = "WN10-AC-000030"
$policyName = "MinimumPasswordAge" # Name used in secedit inf files
$requiredValue = 1 # Minimum acceptable value in days
$friendlyName = "Minimum password age" # User-friendly name for messages

# Temporary file paths for secedit operations
$tempExportPath = Join-Path -Path $env:TEMP -ChildPath "SecPolExport_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
$tempImportPath = Join-Path -Path $env:TEMP -ChildPath "SecPolImport_$(Get-Date -Format 'yyyyMMddHHmmss').inf"

Write-Host "Starting check for STIG ID: $stigId ($friendlyName)..."

# Function to clean up temporary files
function Cleanup-TempFiles {
    if (Test-Path $tempExportPath) {
        Remove-Item -Path $tempExportPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $tempImportPath) {
        Remove-Item -Path $tempImportPath -Force -ErrorAction SilentlyContinue
    }
}

try {
    # Export current local security policy using secedit
    Write-Host "Exporting current local security policy to $tempExportPath..."
    secedit.exe /export /cfg "$tempExportPath" /quiet
    # Short delay to ensure file is written before reading
    Start-Sleep -Seconds 1

    if (-not (Test-Path $tempExportPath)) {
        throw "Failed to export security policy. Check secedit permissions or path."
    }

    # Read the exported policy file and find the current setting
    $currentSettingLine = Get-Content -Path $tempExportPath | Select-String -Pattern "^\s*$policyName\s*=" -CaseSensitive
    $currentValue = -1 # Default to a value indicating not found or invalid

    if ($currentSettingLine) {
        try {
            $currentValue = [int]($currentSettingLine.Line.Split('=')[1].Trim())
            Write-Host "Current '$friendlyName' value found: $currentValue"
        } catch {
            Write-Warning "Could not parse current value for '$friendlyName' from line: $($currentSettingLine.Line)"
            # Treat parse failure as non-compliant to force correction
            $currentValue = -1
        }
    } else {
        Write-Host "'$friendlyName' not explicitly defined in local policy. Assuming non-compliant to ensure setting."
        # Treat not found as non-compliant to ensure it gets set
        $currentValue = -1
    }

    # Check compliance
    if ($currentValue -ge $requiredValue) {
        Write-Host "[COMPLIANT] STIG ID: $stigId - '$friendlyName' is set to $currentValue day(s), which meets the requirement of at least $requiredValue day(s)."
    } else {
        Write-Warning "[NON-COMPLIANT] STIG ID: $stigId - '$friendlyName' is set to $currentValue day(s). Requirement is at least $requiredValue day(s)."
        Write-Host "Attempting remediation..."

        # Create the .inf content for import
        $infContent = @"
[Unicode]
Unicode=yes
[System Access]
$policyName = $requiredValue
[Version]
signature="`$CHICAGO`$"
Revision=1
"@

        # Write the content to the temporary import file using Unicode encoding
        Set-Content -Path $tempImportPath -Value $infContent -Encoding Unicode -Force
        Write-Host "Created temporary policy file for import: $tempImportPath"

        # Apply the setting using secedit
        Write-Host "Applying updated setting using secedit..."
        # Use the standard security database path
        $secDbPath = Join-Path -Path $env:SystemRoot -ChildPath "security\database\secedit.sdb"
        $processInfo = Start-Process secedit.exe -ArgumentList "/configure /db ""$secDbPath"" /cfg ""$tempImportPath"" /areas SECURITYPOLICY /quiet" -Wait -PassThru -NoNewWindow

        if ($processInfo.ExitCode -eq 0) {
            Write-Host "[REMEDIATED] STIG ID: $stigId - Successfully configured '$friendlyName' to $requiredValue day(s)."
            # Optional: Re-verify by exporting and checking again, though secedit success usually suffices.
        } else {
            throw "Failed to apply security policy using secedit. Exit code: $($processInfo.ExitCode)"
        }
    }
}
catch {
    Write-Error "An error occurred during STIG check/remediation for $stigId: $($_.Exception.Message)"
    # Consider adding more detailed error logging here if needed
}
finally {
    # Clean up temporary files
    Write-Host "Cleaning up temporary files..."
    Cleanup-TempFiles
    Write-Host "Script finished for STIG ID: $stigId."
}
