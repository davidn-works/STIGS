<#
.SYNOPSIS
  This PowerShell script disables Internet Explorer 11 on Windows 10.

.NOTES
  Author          : David N.
  LinkedIn        : N/A
  GitHub          : github.com/davidn-works
  Date Created    : 2025-03-18
  Last Modified   : 2025-03-18
  Version         : 1.1
  CVEs            : N/A
  Plugin IDs      : N/A
  STIG-ID         : WN10-CC-000391

.TESTED ON
  Date(s) Tested  : 
  Tested By       : 
  Systems Tested  : 
  PowerShell Ver. : 

.USAGE
  Run the script with administrative privileges.  It will check if IE11 is installed and, if so, disable it.
  Example syntax:
  PS C:> .__remediation_template(STIG-ID-WN10-CC-000391).ps1
#>

# Check if the script is running with administrative privileges.  Exit if not.
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Warning "This script must be run as an administrator.  Exiting."
  exit 1
}

# Check if IE 11 feature is installed.
try {
    $ieFeature = Get-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -ErrorAction Stop
    $ieInstalled = $true
    Write-Host "Internet Explorer 11 is installed."
}
catch {
    $ieInstalled = $false
    Write-Host "Internet Explorer 11 is not installed."
}

# Disable IE 11 if installed and enabled.
if ($ieInstalled) {
    if ($ieFeature.State -eq "Enabled")
    {
      Write-Host "Internet Explorer 11 is enabled.  Disabling..."
      try {
          Disable-WindowsOptionalFeature -Online -FeatureName "Internet-Explorer-Optional-amd64" -NoRestart -ErrorAction Stop
          Write-Host "Internet Explorer 11 has been disabled."

          # Set the registry key to disable IE11 as a standalone browser. This is the GP equivalent.
          $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"
          $name = "DisableInternetExplorerApp"
          $value = 1

          if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "Created registry path: $registryPath"
          }
          New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
          Write-Host "Set registry key to disable IE11 as a standalone browser."
          Write-Host "A reboot is required for changes to take effect."

      }
      catch {
          Write-Error "Failed to disable Internet Explorer 11: $($_.Exception.Message)"
          exit 1
      }
    } else {
        Write-Host "Internet Explorer 11 is already disabled."
    }
}

Write-Host "Script completed."
exit 0
