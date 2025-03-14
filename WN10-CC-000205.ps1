<#
.SYNOPSIS
This PowerShell script checks and sets the Windows Telemetry setting to either "Security" (0) or "Basic" (1),
or "Enhanced" (2) if Windows 10 v1709 or later is used and Windows Analytics requirements are met.

.NOTES
    Author          : David N.
    LinkedIn        : 
    GitHub          : github.com/davidn-works
    Date Created    : 2025-03-14
    Last Modified   : 2025-03-14
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : STIG-ID-WN10-CC-000205

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
Run the script with administrator privileges.  It will check the current setting and, if necessary,
set the 'AllowTelemetry' registry value to the appropriate level based on the STIG requirements.

Example syntax:
PS C:> .__remediation_template(STIG-ID-WN10-CC-000205).ps1
#>

# Registry path for the telemetry setting
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$valueName = "AllowTelemetry"
$expectedValues = @(0, 1, 2)  # Allowed values: 0 (Security), 1 (Basic), 2 (Enhanced - under specific conditions)


# Check if the registry key exists. Create if it doesn't.
if (-not (Test-Path -Path $regPath)) {
    try {
        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
        Write-Host "Registry key '$regPath' created." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to create registry key '$regPath': $($_.Exception.Message)"
        exit 1  # Exit with a non-zero code to indicate failure
    }
}


# Get the current AllowTelemetry value (if it exists)
try {
  $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName
}
catch [System.Management.Automation.ItemNotFoundException] {
    # The value does not exist, which is a finding.  We will create it.
    $currentValue = $null  # Set to null to clearly indicate it wasn't found
}
catch {
  Write-Warning "Error getting registry value: $($_.Exception.Message)"
  exit 1
}


# Determine the appropriate setting and set it if needed.
if ($currentValue -notin $expectedValues) {

    # Check Windows version for Enhanced (2) option
    $osVersion = [System.Environment]::OSVersion.Version
    $allowEnhanced = $false

    if ($osVersion.Major -ge 10 -and $osVersion.Build -ge 16299) { # 16299 is the build number for 1709
      #Check for V-220833 setting (LimitEnhancedDiagnosticData)
      try{
        $limitEnhancedValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticData" -ErrorAction Stop).LimitEnhancedDiagnosticData

        if ($limitEnhancedValue -eq 1) {
          $allowEnhanced = $true
          $newValue = 2
          Write-Host "Windows 10 v1709 or later detected, and LimitEnhancedDiagnosticData is set.  Setting AllowTelemetry to 2 (Enhanced)." -ForegroundColor Green
        }
        else{
          Write-Warning "Windows 10 v1709 or later detected BUT LimitEnhancedDiagnosticData is NOT set to 1. Cannot set AllowTelemetry to Enhanced (2)."
          $newValue = 1 # Default to Basic if LimitEnhancedDiagnosticData isn't set
        }
      }
      catch [System.Management.Automation.ItemNotFoundException]{
        Write-Warning "Windows 10 v1709 or later detected BUT LimitEnhancedDiagnosticData registry value does not exist. Cannot set AllowTelemetry to Enhanced (2)."
        $newValue = 1; # Default to basic
      }
      catch{
         Write-Warning "Error checking for LimitEnhancedDiagnosticData: $($_.Exception.Message)"
          $newValue = 1;
      }
    }
    else
    {
        $newValue = 1  # Default to Basic if not v1709+ or LimitEnhancedDiagnosticData not configured.
    }
      
    if (-not $allowEnhanced -and $newValue -ne 2){
      $newValue = 1 # Set to 1 (Basic) by default
      Write-Host "Setting AllowTelemetry to 1 (Basic)." -ForegroundColor Green
    }

    try {
        Set-ItemProperty -Path $regPath -Name $valueName -Value $newValue -Type DWord -Force -ErrorAction Stop
        Write-Host "Registry value '$valueName' set to '$newValue'." -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to set registry value '$valueName': $($_.Exception.Message)"
        exit 1
    }
}
else {
  if($currentValue -eq 2){
    Write-Host "AllowTelemetry is already set to 2 (Enhanced). Checking LimitEnhancedDiagnosticData..." -ForegroundColor Yellow
    #Double check the LimitEnhancedDiagnosticData, even though it reported correct above
      try{
        $limitEnhancedValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticData" -ErrorAction Stop).LimitEnhancedDiagnosticData

        if ($limitEnhancedValue -eq 1) {
          Write-Host "LimitEnhancedDiagnosticData is correctly configured." -ForegroundColor Green
        }
        else
        {
          Write-Warning "LimitEnhancedDiagnosticData is NOT set to 1. AllowTelemetry should not be set to Enhanced(2)."
        }
      }
       catch [System.Management.Automation.ItemNotFoundException]{
          Write-Warning "LimitEnhancedDiagnosticData registry key not found. AllowTelemetry should not be set to Enhanced (2)."
        }
        catch{
           Write-Warning "Error getting LimitEnhancedDiagnosticData: $($_.Exception.Message)"
        }
  }
  else{
    Write-Host "Registry value '$valueName' is already correctly set to '$currentValue'." -ForegroundColor Green
  }
}

Write-Host "Script completed." -ForegroundColor Green
exit 0 # Explicitly exit with a success code
