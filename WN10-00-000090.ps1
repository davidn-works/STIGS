<#
.SYNOPSIS
    This PowerShell script ensures that no local user accounts have "Password never expires" enabled.
    It unchecks this setting for any affected accounts.

.NOTES
    Author          : David N.
    LinkedIn        : linked.com/in/
    GitHub          : github.com/davidn-works
    Date Created    : 2025-03-14
    Last Modified   : 2025-03-14
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-00-000090

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run the script with administrative privileges.  It will output any users who had the
    "Password never expires" setting enabled and were modified.

    Example syntax:
    PS C:\> .\WN10-00-000090.ps1
#>

# Get all local user accounts, excluding disabled accounts and built-in accounts.
$users = Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.SID -notlike "S-1-5-21*-500" -and $_.SID -notlike "S-1-5-18" -and $_.SID -notlike "S-1-5-19" -and $_.SID -notlike "S-1-5-20"}  # Exclude Administrator, System, LocalService, NetworkService


# Iterate through each user and check the "Password never expires" setting.
foreach ($user in $users) {
    if ($user.PasswordNeverExpires) {
        # If "Password never expires" is enabled, disable it.
        try {
            Set-LocalUser -Name $user.Name -PasswordNeverExpires:$false -ErrorAction Stop
            Write-Host "Remediation: 'Password never expires' has been DISABLED for user: $($user.Name)" -ForegroundColor Green
        }
        catch {
            Write-Warning "Failed to modify 'Password never expires' for user: $($user.Name). Error: $($_.Exception.Message)"
        }
    } else {
         Write-Host "Compliant: 'Password never expires' is already disabled for user: $($user.Name)" -ForegroundColor Yellow
    }
}

Write-Host "Script completed." -ForegroundColor Cyan
