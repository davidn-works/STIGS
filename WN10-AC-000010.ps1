<#
.SYNOPSIS
This PowerShell script enforces STIG WN10-AC-000010 by ensuring the account lockout threshold is set to 3 or less (but not 0).

.NOTES
Author          : David N.
LinkedIn        : 
GitHub          : https://github.com/davidn-works
Date Created    : 2025-04-01
Last Modified   : 2025-04-01
Version         : 1.0
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN10-AC-000010
Vulnerability Id: V-220740
SRG             : SRG-OS-000021-GPOS-00005
CCI             : CCI-000044

.DESCRIPTION
The script checks the local security policy for the 'Account lockout threshold'.
According to STIG WN10-AC-000010, this value must be greater than 0 and less than or equal to 3.
If the current setting is non-compliant (0 or greater than 3), the script configures it to 3.

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with elevated privileges (Administrator).
Example syntax:
PS C:\Scripts> .\Set-Stig-WN10-AC-000010.ps1

.REQUIREMENTS
Requires administrative privileges to modify local security policies.
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

Write-Host "Starting STIG WN10-AC-000010 Check & Remediation..."
Write-Host "STIG ID: WN10-AC-000010 - Account lockout threshold"
Write-Host "Rule: Must be configured to 3 or less invalid logon attempts (excluding 0)."

$stigId = "WN10-AC-000010"
$desiredThreshold = 3 # Recommended compliant value meeting "3 or less (but not 0)"
$policyName = "LockoutBadCount" # Name in secedit inf file
$policySection = "[System Access]"

# Define temporary file paths for secedit
$tempDir = $env:TEMP
$exportFile = Join-Path -Path $tempDir -ChildPath "SecPolExport_$($stigId)_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
$importFile = Join-Path -Path $tempDir -ChildPath "SecPolImport_$($stigId)_$(Get-Date -Format 'yyyyMMddHHmmss').inf"
$logFile = Join-Path -Path $tempDir -ChildPath "SecPolConfig_$($stigId)_$(Get-Date -Format 'yyyyMMddHHmmss').log"

$currentValue = -1 # Initialize with an invalid value

# --- Check Current Setting ---
Write-Host "Checking current 'Account lockout threshold' setting..."
try {
    # Export current security policy to a temporary file
    secedit.exe /export /cfg "$exportFile" /quiet
    if ($LASTEXITCODE -ne 0) {
        throw "Secedit export failed with exit code $LASTEXITCODE."
    }

    # Read the exported file and find the setting
    $configFileContent = Get-Content -Path $exportFile
    $settingLine = $configFileContent | Where-Object { $_ -match "^\s*$($policyName)\s*=" }

    if ($settingLine) {
        $currentValue = ($settingLine -split '=')[1].Trim()
        if ($currentValue -eq '0') {
            Write-Warning "Current 'Account lockout threshold' is $currentValue (Account lockout is disabled)."
        } else {
            Write-Host "Current 'Account lockout threshold' is $currentValue."
        }
    } else {
        # If the setting isn't explicitly in the export, it might be default (0) or inherited.
        # We'll treat absence as potentially non-compliant and attempt to set it.
        Write-Warning "'$policyName' not explicitly found in local policy export. Assuming potentially non-compliant."
        $currentValue = 0 # Assume non-compliant if not found explicitly for check logic
    }
} catch {
    Write-Error "Error checking current setting for $stigId`: $_"
    # Clean up export file if created
    if (Test-Path $exportFile) { Remove-Item -Path $exportFile -Force -ErrorAction SilentlyContinue }
    # Exit script if check fails critically
    exit 1
}

# --- Evaluate Compliance ---
$isCompliant = $false
if ([int]$currentValue -ge 1 -and [int]$currentValue -le 3) {
    $isCompliant = $true
    Write-Host "[COMPLIANT] Account lockout threshold ($currentValue) meets STIG requirements (1-3)." -ForegroundColor Green
} else {
    Write-Warning "[NON-COMPLIANT] Account lockout threshold ($currentValue) does not meet STIG requirements (Must be 1-3)."
}

# --- Apply Fix if Necessary ---
if (-not $isCompliant) {
    Write-Host "Attempting remediation: Setting 'Account lockout threshold' to $desiredThreshold..."
    try {
        # Ensure the [System Access] section exists and prepare the setting line
        $sectionFound = $false
        $settingFound = $false
        $newContent = [System.Collections.Generic.List[string]]::new()

        foreach ($line in $configFileContent) {
            if ($line.Trim() -eq $policySection) {
                $sectionFound = $true
                $newContent.Add($line)
            } elseif ($sectionFound -and $line -match "^\s*$($policyName)\s*=") {
                $newContent.Add("$policyName = $desiredThreshold")
                $settingFound = $true
                # Continue processing lines, but mark section as processed regarding this setting
                $sectionFound = $false # Prevents adding the setting again if section appears later (unlikely)
            } elseif ($sectionFound -and $line.Trim().StartsWith("[")) {
                 # We reached the next section without finding the setting
                 if (-not $settingFound) {
                    $newContent.Add("$policyName = $desiredThreshold") # Add setting before the new section
                    $settingFound = $true
                 }
                 $newContent.Add($line)
                 $sectionFound = $false # Reset section flag
            }
            else {
                 $newContent.Add($line)
            }
        }

        # If the section was found but the setting wasn't added by the end of the file
        if ($sectionFound -and -not $settingFound) {
             $newContent.Add("$policyName = $desiredThreshold")
             $settingFound = $true
        }

        # If the entire [System Access] section was missing (highly unlikely for default template)
        if (-not $sectionFound -and -not $settingFound) {
            Write-Warning "'$policySection' section not found. Adding section and setting."
            $newContent.Add($policySection)
            $newContent.Add("$policyName = $desiredThreshold")
        }

        # Write the modified content to the import file
        Set-Content -Path $importFile -Value $newContent -Encoding ASCII # Secedit often prefers ASCII/ANSI

        # Import the modified settings using secedit
        Write-Host "Applying configuration using secedit..."
        secedit.exe /configure /db secedit.sdb /cfg "$importFile" /log "$logFile" /quiet
        if ($LASTEXITCODE -ne 0) {
            throw "Secedit configuration failed with exit code $LASTEXITCODE. Check log: $logFile"
        }

        Write-Host "[REMEDIATED] Successfully configured 'Account lockout threshold' to $desiredThreshold." -ForegroundColor Green

        # Optional: Force group policy update if needed, though secedit often applies immediately for local policy
        # Write-Host "Running gpupdate /force..."
        # gpupdate /force /quiet

    } catch {
        Write-Error "Error applying remediation for $stigId`: $_"
        # Exit script if fix fails
        exit 1
    } finally {
         # Clean up temporary files
        Write-Verbose "Cleaning up temporary files..."
        Remove-Item -Path $exportFile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $importFile -Force -ErrorAction SilentlyContinue
        # Keep the log file in case of errors during configure step, or remove it too:
        # Remove-Item -Path $logFile -Force -ErrorAction SilentlyContinue
        Write-Verbose "Log file saved to $logFile" # Inform user where log is if kept
    }
} else {
    Write-Host "No remediation required."
}

Write-Host "Finished STIG WN10-AC-000010 Check & Remediation."
