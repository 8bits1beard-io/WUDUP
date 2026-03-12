#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Remediation Script - Configures device for Windows Update for Business.

.DESCRIPTION
    Intune Proactive Remediation script. Runs when WUDUP-Detect.ps1 reports
    non-compliant (device not managed by WUfB).

    Actions:
    1. Removes WSUS configuration (WUServer, UseWUServer, etc.)
    2. Sets PolicyDrivenUpdateSource keys to direct all updates to Windows Update
    3. Applies deferral policies for feature and quality updates
    4. Optionally sets compliance deadlines, version pin, and active hours

    All settings are configurable via the CONFIGURATION section below.

    Exit 0 = Remediation succeeded
    Exit 1 = Remediation failed

.NOTES
    Author:  Device-DNA Project
    Tool:    WUDUP Remediation v1.1.0
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  CONFIGURATION — Edit these values to match your organization's policy
# ============================================================================

# Deferral periods
$Config_FeatureDeferralDays = 30       # 0-365, Microsoft recommends 30-90
$Config_QualityDeferralDays = 7        # 0-30, Microsoft recommends 3-7

# Compliance deadlines (set to $null to skip)
$Config_FeatureDeadlineDays = 7        # Days after deferral to force install ($null = not set)
$Config_QualityDeadlineDays = 3        # Days after deferral to force install ($null = not set)
$Config_DeadlineGracePeriod = 2        # Grace period before forced reboot ($null = not set)

# Version pinning (set both to $null to skip)
$Config_ProductVersion      = $null    # 'Windows 10' or 'Windows 11' ($null = not set)
$Config_TargetVersion       = $null    # e.g., '24H2' ($null = not set)

# Auto-update behavior
$Config_AUOption            = 3        # 2=Notify, 3=Auto download+notify, 4=Auto+schedule, 5=Local admin

# Driver exclusion (set to $null to skip)
$Config_ExcludeDrivers      = $null    # 1 = exclude drivers from WU, 0 = include, $null = not set

# ============================================================================
#  REGISTRY PATHS
# ============================================================================

$RegPath_WU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

# ============================================================================
#  HELPERS
# ============================================================================

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        if (Test-Path -Path $Path) {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $item.$Name
        }
    }
    catch { }
    return $null
}

function Ensure-Path {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Set-RegDWord {
    param([string]$Path, [string]$Name, [int]$Value)
    Ensure-Path -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-RegString {
    param([string]$Path, [string]$Name, [string]$Value)
    Ensure-Path -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    if (Test-Path $Path) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

# ============================================================================
#  REMEDIATION
# ============================================================================

try {
    $changes = @()

    # --- Step 1: Remove WSUS configuration ---
    $wsusValues = @(
        @{ Path = $RegPath_WU; Name = 'WUServer' },
        @{ Path = $RegPath_WU; Name = 'WUStatusServer' },
        @{ Path = $RegPath_WU; Name = 'DoNotConnectToWindowsUpdateInternetLocations' },
        @{ Path = $RegPath_WU; Name = 'SetDisableUXWUAccess' },
        @{ Path = $RegPath_AU; Name = 'UseWUServer' }
    )

    foreach ($item in $wsusValues) {
        $current = Get-RegValue -Path $item.Path -Name $item.Name
        if ($null -ne $current) {
            Remove-RegValue -Path $item.Path -Name $item.Name
            $changes += "Removed $($item.Name)"
        }
    }

    # --- Step 2: Set PolicyDrivenUpdateSource (Windows 10 2004+ / Windows 11) ---
    $sourceKeys = @(
        'SetPolicyDrivenUpdateSourceForFeatureUpdates',
        'SetPolicyDrivenUpdateSourceForQualityUpdates',
        'SetPolicyDrivenUpdateSourceForDriverUpdates',
        'SetPolicyDrivenUpdateSourceForOtherUpdates'
    )

    foreach ($key in $sourceKeys) {
        Set-RegDWord -Path $RegPath_WU -Name $key -Value 0
    }
    $changes += 'Set PolicyDrivenUpdateSource (all types -> WU)'

    # --- Step 3: Set deferral policies ---
    Set-RegDWord -Path $RegPath_WU -Name 'DeferFeatureUpdatesPeriodInDays' -Value $Config_FeatureDeferralDays
    Set-RegDWord -Path $RegPath_WU -Name 'DeferQualityUpdatesPeriodInDays' -Value $Config_QualityDeferralDays
    $changes += "Deferrals: Feature=${Config_FeatureDeferralDays}d, Quality=${Config_QualityDeferralDays}d"

    # --- Step 4: Set compliance deadlines (if configured) ---
    if ($null -ne $Config_FeatureDeadlineDays) {
        Set-RegDWord -Path $RegPath_WU -Name 'ConfigureDeadlineForFeatureUpdates' -Value $Config_FeatureDeadlineDays
        $changes += "Feature deadline: ${Config_FeatureDeadlineDays}d"
    }
    if ($null -ne $Config_QualityDeadlineDays) {
        Set-RegDWord -Path $RegPath_WU -Name 'ConfigureDeadlineForQualityUpdates' -Value $Config_QualityDeadlineDays
        $changes += "Quality deadline: ${Config_QualityDeadlineDays}d"
    }
    if ($null -ne $Config_DeadlineGracePeriod) {
        Set-RegDWord -Path $RegPath_WU -Name 'ConfigureDeadlineGracePeriod' -Value $Config_DeadlineGracePeriod
        $changes += "Grace period: ${Config_DeadlineGracePeriod}d"
    }

    # --- Step 5: Set version pin (if configured) ---
    if ($null -ne $Config_ProductVersion -and $null -ne $Config_TargetVersion) {
        Set-RegDWord  -Path $RegPath_WU -Name 'TargetReleaseVersion' -Value 1
        Set-RegString -Path $RegPath_WU -Name 'TargetReleaseVersionInfo' -Value $Config_TargetVersion
        Set-RegString -Path $RegPath_WU -Name 'ProductVersion' -Value $Config_ProductVersion
        $changes += "Version pin: $Config_ProductVersion $Config_TargetVersion"
    }
    else {
        # Ensure no stale version pin
        Remove-RegValue -Path $RegPath_WU -Name 'TargetReleaseVersion'
        Remove-RegValue -Path $RegPath_WU -Name 'TargetReleaseVersionInfo'
        Remove-RegValue -Path $RegPath_WU -Name 'ProductVersion'
    }

    # --- Step 6: Set auto-update behavior ---
    Set-RegDWord -Path $RegPath_AU -Name 'NoAutoUpdate' -Value 0
    Set-RegDWord -Path $RegPath_AU -Name 'AUOptions' -Value $Config_AUOption
    $changes += "AU option: $Config_AUOption"

    # --- Step 7: Driver exclusion (if configured) ---
    if ($null -ne $Config_ExcludeDrivers) {
        Set-RegDWord -Path $RegPath_WU -Name 'ExcludeWUDriversInQualityUpdate' -Value $Config_ExcludeDrivers
        $driverLabel = if ($Config_ExcludeDrivers -eq 1) { 'excluded' } else { 'included' }
        $changes += "Drivers: $driverLabel"
    }

    # --- Step 8: Clean up stale pause entries ---
    $pauseValues = @(
        'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
        'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime'
    )
    foreach ($v in $pauseValues) {
        Remove-RegValue -Path $RegPath_WU -Name $v
    }

    # --- Done ---
    $summary = $changes -join '; '
    Write-Output "REMEDIATED: WUfB configured. $summary"
    exit 0
}
catch {
    Write-Output "ERROR: Remediation failed - $($_.Exception.Message)"
    exit 1
}
