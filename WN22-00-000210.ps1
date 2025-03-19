<#
.SYNOPSIS
This PowerShell script checks and remediates the "Password Never Expires" setting for user accounts on Windows Server 2022,
complying with STIG ID WN22-00-000210.

.NOTES
Author          : David N.
LinkedIn        : N/A
GitHub          : N/A
Date Created    : 2025-03-19
Last Modified   : 2025-03-19
Version         : 1.1
CVEs            : N/A
Plugin IDs      : N/A
STIG-ID         : WN22-00-000210
Vulnerability Id: V-254258

.TESTED ON
Date(s) Tested  : 
Tested By       : 
Systems Tested  : 
PowerShell Ver. : 

.USAGE
Run the script with elevated privileges (Run as Administrator).  The script will first check for non-compliant accounts
and then prompt the user to remediate them.  It handles both domain and local accounts appropriately.

Example syntax:
PS C:\> . .\WN22-00-000210.ps1

.DESCRIPTION
The script checks for accounts with 'PasswordNeverExpires' set to True (domain) or 'PasswordExpires' set to False (local).
It excludes known system accounts and disabled accounts.  It provides a remediation option using a confirmation prompt.
#>

# Function to check and remediate domain accounts
function Check-DomainAccounts {
    Write-Host "Checking Domain Accounts..." -ForegroundColor Yellow

    $NonCompliantUsers = Search-ADAccount -PasswordNeverExpires -UsersOnly | Where-Object {$_.Enabled -eq $true -and $_.Name -notin @("DefaultAccount", "Guest", "krbtgt")}

    if ($NonCompliantUsers) {
        Write-Host "Non-compliant domain users found:" -ForegroundColor Red
        $NonCompliantUsers | FT Name, PasswordNeverExpires, Enabled

        $Remediate = Read-Host "Do you want to remediate these domain accounts (set passwords to expire)? (y/n)"
        if ($Remediate -eq "y") {
            foreach ($User in $NonCompliantUsers) {
                try {
                    Set-ADUser -Identity $User.SamAccountName -PasswordNeverExpires $false -ErrorAction Stop
                    Write-Host "Remediated: $($User.Name)" -ForegroundColor Green
                }
                catch {
                    Write-Host "Error remediating $($User.Name): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "Remediation skipped for domain accounts." -ForegroundColor Yellow
        }
    } else {
        Write-Host "No non-compliant domain users found." -ForegroundColor Green
    }
}

# Function to check and remediate local accounts
function Check-LocalAccounts {
    Write-Host "Checking Local Accounts..." -ForegroundColor Yellow

    $NonCompliantUsers = Get-CimInstance -Class Win32_Useraccount -Filter "PasswordExpires=False and LocalAccount=True and Disabled=False" | Where-Object {$_.Name -notin @("DefaultAccount", "Guest", "Administrator")} #Exclude Administrator

    if ($NonCompliantUsers) {
        Write-Host "Non-compliant local users found:" -ForegroundColor Red
        $NonCompliantUsers | FT Name, PasswordExpires, Disabled, LocalAccount

        $Remediate = Read-Host "Do you want to remediate these local accounts (set passwords to expire)? (y/n)"
        if ($Remediate -eq "y") {
            foreach ($User in $NonCompliantUsers) {
                try {
                  #Use net user to set password to expire.
                  net user $User.Name /PasswordExpires:yes
                  Write-Host "Remediated: $($User.Name)" -ForegroundColor Green
                }
                catch {
                    Write-Host "Error remediating $($User.Name): $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "Remediation skipped for local accounts." -ForegroundColor Yellow
        }
    } else {
        Write-Host "No non-compliant local users found." -ForegroundColor Green
    }
}


# --- Main Script ---

# Check if running in a domain environment
if ($env:USERDOMAIN -ne $env:COMPUTERNAME) {
    # Domain Environment
    try {
      Import-Module ActiveDirectory -ErrorAction Stop #Import if it's not already imported.
      Check-DomainAccounts
    }
    catch
    {
      Write-Host "Active Directory module not found or error loading.  Error: $($_.Exception.Message)" -ForegroundColor Red
      Write-Host "Skipping domain account check." -ForegroundColor Yellow
    }
} else {
    # Local/Workgroup Environment
    Check-LocalAccounts
}

Write-Host "Script completed." -ForegroundColor Cyan
