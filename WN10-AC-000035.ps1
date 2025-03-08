<#
.SYNOPSIS
    This STIG requires enabling detailed logging of PowerShell script execution. This is crucial for auditing and incident response, as it allows you to see exactly what commands and scripts were run. It aids in detecting malicious PowerShell activity.

.NOTES
    Author          : David N.
    LinkedIn        : linkedin.com/in
    GitHub          : github.com/davidn-works
    Date Created    : 2025-03-07  
    Last Modified   : 2025-03-07
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000035

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
Save the code as a .ps1 file (e.g., WN10-AC-000035.ps1).

Open PowerShell as an administrator. This is crucial because modifying security settings requires elevated privileges.

Navigate to the directory where you saved the file and run the script
#>

# STIG ID: WN10-AC-000035
# SRG: SRG-OS-000078-GPOS-00046
# Severity: medium
# CCI: CCI-004066,CCI-000205,CCI-000205
# Vulnerability Id: V-220745
# Description: Passwords must, at a minimum, be 14 characters.

# --- Check ---
function Check-MinimumPasswordLength {
    try {
        $minLength = (Get-WmiObject -Class Win32_AccountPolicy -Namespace "root\cimv2\Security" -Filter "Authority = '$env:USERDOMAIN'").MinPasswordLength
        if ($minLength -lt 14) {
            Write-Warning "Minimum password length is less than 14 characters.  Current length: $minLength"
            return $false
        } else {
            Write-Host "Minimum password length is configured correctly (14 characters or more)." -ForegroundColor Green
            return $true
        }
    }
    catch {
        Write-Error "Error checking minimum password length: $($_.Exception.Message)"
        return $false # Assume failure if there's an error.
    }
}


# --- Fix ---
function Set-MinimumPasswordLength {
    try {
        # Use net accounts to set the minimum password length.  This is the most reliable method.
        $command = "net accounts /minpwlen:14"
        Invoke-Expression $command | Out-Null  # Suppress output

        # Verify the change
        Start-Sleep -Seconds 2 #Give it a little time to propogate.
        if (Check-MinimumPasswordLength) {
            Write-Host "Successfully set minimum password length to 14 characters." -ForegroundColor Green
            return $true
        } else {
            Write-Warning "Failed to set minimum password length to 14 characters."
            return $false
        }

    }
    catch {
        Write-Error "Error setting minimum password length: $($_.Exception.Message)"
        return $false
    }
}

# --- Remediation Script ---

# Check the current setting
if (-not (Check-MinimumPasswordLength)) {
    Write-Host "Remediating..."
    # Attempt to fix the setting
    if (Set-MinimumPasswordLength) {
        Write-Host "Remediation successful." -ForegroundColor Green
    } else {
        Write-Error "Remediation failed.  Manual intervention required."
        Exit 1  # Exit with a non-zero code to indicate failure.
    }
} else {
    Write-Host "The system is already compliant." -ForegroundColor Green
    Exit 0  # Exit with a zero code to indicate success (already compliant).
}

# --- Optional:  Using Group Policy (Less reliable for local accounts) ---
# This section is commented out because using 'net accounts' is generally more reliable for local accounts.
# If you *must* use Group Policy, you can uncomment this section, but be aware of the caveats.
# Also, this requires running as an administrator with permissions to modify Group Policy.
<#
function Set-MinimumPasswordLength-GP {
    try {
        # Import the Group Policy module
        Import-Module GroupPolicy

        # Get the default domain policy (or the appropriate GPO if not the default)
        $gpo = Get-GPO -Name "Default Domain Policy"

        # Set the minimum password length
        Set-GPRegistryValue -Name $gpo.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SeCEdit\Reg Values\MACHINE\System\CurrentControlSet\Control\Lsa\MinimumPasswordLength" -ValueName "" -Type DWord -Value 14

        # Force a Group Policy update
        gpupdate /force

        # Verification is handled by the Check-MinimumPasswordLength function

        Write-Host "Successfully set minimum password length to 14 via Group Policy (Default Domain Policy)."
    }
    catch {
        Write-Error "Error setting minimum password length via Group Policy: $($_.Exception.Message)"
    }
}
#>

# --- Optional:  Using secedit (also less reliable than 'net accounts') ---
#  This part is commented out, as `net accounts` is the preferred approach.  This is
#  provided as an alternative if `net accounts` is not available or suitable for some reason.

<#
function Set-MinimumPasswordLength-Secedit {
    try {
        # Create a temporary INF file
        $infFile = "$env:TEMP\temp_security_policy.inf"

        # Create the INF file content
        $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO$`"
Revision=1
[System Access]
MinimumPasswordLength = 14
"@

        # Write the INF content to the file
        $infContent | Out-File -FilePath $infFile -Encoding unicode

        # Apply the security template
        secedit /configure /db "$env:SystemRoot\security\database\temp_secedit.sdb" /cfg $infFile /overwrite /quiet

        # Clean up the temporary INF file
        Remove-Item -Path $infFile -Force
      	Remove-Item -Path "$env:SystemRoot\security\database\temp_secedit.sdb" -Force -ErrorAction SilentlyContinue

        Write-Host "Successfully set minimum password length to 14 using secedit."

    }
    catch {
        Write-Error "Error setting minimum password length using secedit: $($_.Exception.Message)"
    }
}
#>
