<#
.SYNOPSIS
    This PowerShell script ensures that the maximum size of the Windows Application event log is at least 32768 KB (32 MB).

.NOTES
    Author          : David N.
    LinkedIn        : linkedin.com/in
    GitHub          : github.com/davidn-works
    Date Created    : 2025-02-28
    Last Modified   : 2025-02-28
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Open Powershell ISE as an administrator and paste the following code below to remediate the STIG.
#>

# Specify the registry key path
$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"

# Specify the value name
$ValueName = "MaxSize"

# Specify the value data (8 MB in hexadecimal)
$ValueData = 0x00008000  # Equivalent to 32768 KB, or 32 MB.  Original requested 8 MB would have been 0x00002000 (8192KB)

# Check if the registry key exists.  If not, create it.
if (-not (Test-Path -Path $RegistryPath)) {
    try {
        New-Item -Path $RegistryPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Registry key '$RegistryPath' created." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create registry key '$RegistryPath': $($_.Exception.Message)"
        exit 1  # Exit with an error code
    }
}

# Set the registry value
try {
    New-ItemProperty -Path $RegistryPath -Name $ValueName -Value $ValueData -PropertyType DWord -Force -ErrorAction Stop | Out-Null
    Write-Host "Registry value '$ValueName' set to 0x$($ValueData.ToString('X8')) (DWORD) in '$RegistryPath'." -ForegroundColor Green
}
catch {
    Write-Error "Failed to set registry value '$ValueName' in '$RegistryPath': $($_.Exception.Message)"
    exit 1
}

# Verify the value was set correctly (optional, but good practice)
try {
    $ActualValue = (Get-ItemProperty -Path $RegistryPath -Name $ValueName).$ValueName
    if ($ActualValue -eq $ValueData) {
        Write-Host "Verification successful. Value is set correctly." -ForegroundColor Green
    }
    else {
        Write-Warning "Verification failed. Expected value: 0x$($ValueData.ToString('X8')), Actual value: 0x$($ActualValue.ToString('X8'))"
    }
}
catch {
    Write-Warning "Verification failed. Could not read the registry value: $($_.Exception.Message)"
}

#Requires -RunAsAdministrator # Add this to the beginning of the script if you are getting access denied.
Write-Host "Script completed."
