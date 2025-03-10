<#
.SYNOPSIS
    This PowerShell script ensures that the built-in guest account is disabled.

.NOTES
    Author          : David N.
    LinkedIn        : linkedin.com/in/
    GitHub          : github.com/davidn-works
    Date Created    : 2025-03-09
    Last Modified   : 2025-03-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-SO-000010

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run the script with administrative privileges.  The script will check and, if necessary, remediate the Guest account status.

    Example syntax:
    PS C:\> .\WN10-SO-000010_Remediation.ps1
#>

# Get the Guest account object.
$GuestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

# Check if the Guest account exists and its status.
if ($GuestAccount) {
    if ($GuestAccount.Enabled) {
        Write-Warning "The Guest account is currently enabled.  Disabling..."
        try {
            Disable-LocalUser -Name "Guest" -ErrorAction Stop
            Write-Host "The Guest account has been successfully disabled." -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to disable the Guest account: $($_.Exception.Message)"
            exit 1 # Exit with a non-zero code to indicate failure
        }
    }
    else {
        Write-Host "The Guest account is already disabled." -ForegroundColor Green
        exit 0
    }
}
else
{
   Write-Host "Guest Account Not Found. Presumed removed or renamed. Compliant by design." -ForegroundColor Green
   exit 0 #no guest, is compliant!
}

#Verify
$GuestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($GuestAccount.Enabled -eq $False)
{
        Write-Host "Verification: Guest account is disabled." -ForegroundColor Green
}
else
{
        Write-Host "Verification: Guest account is enabled. Non-Compliant" -ForegroundColor Red
        exit 1
}
