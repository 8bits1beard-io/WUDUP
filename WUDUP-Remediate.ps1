#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Remediation Script - Configures device for Windows Update for Business.

.DESCRIPTION
    Intune Proactive Remediation script. Runs when WUDUP-Detect.ps1 reports
    non-compliant (device not managed by WUfB).

    Actions:
    1. Checks for SCCM — warns and exits if WU workload is not shifted
    2. Removes WSUS configuration (WUServer, WUStatusServer, UseWUServer, etc.)
    3. Sets PolicyDrivenUpdateSource keys to direct all updates to Windows Update
    4. Applies deferral policies for feature and quality updates
    5. Optionally sets compliance deadlines, version pin, driver exclusion

    All settings are configurable via the CONFIGURATION section below.

    Exit 0 = Remediation succeeded
    Exit 1 = Remediation failed

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Remediation v1.2.0
    Created: 12 March 2026
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

# SCCM behavior: set to $true to allow remediation even on SCCM-managed devices
$Config_AllowOnSCCM         = $false   # $false = skip remediation if SCCM manages WU workload

# ============================================================================
#  REGISTRY PATHS
# ============================================================================

$RegPath_WU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

# ============================================================================
#  HELPERS
# ============================================================================

function Get-SafeRegistryValue {
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

function Ensure-RegistryPath {
    param([string]$Path)
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

function Set-RegDWord {
    param([string]$Path, [string]$Name, [int]$Value)
    Ensure-RegistryPath -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Set-RegString {
    param([string]$Path, [string]$Name, [string]$Value)
    Ensure-RegistryPath -Path $Path
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    try {
        $logDir = Join-Path $env:ProgramData 'WUDUP\Logs'
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $logFile = Join-Path $logDir 'remediate.log'
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -Path $logFile -Value "[$timestamp] $Message" -ErrorAction SilentlyContinue
    }
    catch { }
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
    Write-Log "Remediation started"
    $changes = @()

    # --- Step 0: SCCM guard ---
    $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
    $hasSCCM = ($null -ne $sccmService -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))

    if ($hasSCCM) {
        # Check if co-management has shifted the WU workload to Intune
        $coMgmtFlags = Get-SafeRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
        $wuShiftedToIntune = ($null -ne $coMgmtFlags -and ($coMgmtFlags -band 16) -eq 16)

        if (-not $wuShiftedToIntune -and -not $Config_AllowOnSCCM) {
            $msg = "SKIPPED: SCCM/ConfigMgr manages WU workload. Local changes will be overwritten. Set Config_AllowOnSCCM=true to override."
            Write-Log $msg
            Write-Output $msg
            exit 1
        }

        if ($wuShiftedToIntune) {
            $changes += 'SCCM co-managed (WU->Intune)'
        }
        else {
            $changes += 'WARNING: SCCM active, forced via Config_AllowOnSCCM'
        }
    }

    # --- Step 1: Remove WSUS configuration ---
    $wsusValues = @(
        @{ Path = $RegPath_WU; Name = 'WUServer' },
        @{ Path = $RegPath_WU; Name = 'WUStatusServer' },
        @{ Path = $RegPath_WU; Name = 'DoNotConnectToWindowsUpdateInternetLocations' },
        @{ Path = $RegPath_WU; Name = 'SetDisableUXWUAccess' },
        @{ Path = $RegPath_WU; Name = 'UpdateServiceUrlAlternate' },
        @{ Path = $RegPath_AU; Name = 'UseWUServer' }
    )

    foreach ($item in $wsusValues) {
        $current = Get-SafeRegistryValue -Path $item.Path -Name $item.Name
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
    # Required for PolicyDrivenSource to take effect when set via direct registry write (not GPO/CSP)
    Set-RegDWord -Path $RegPath_AU -Name 'UseUpdateClassPolicySource' -Value 1
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
        'PauseFeatureUpdates', 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
        'PauseQualityUpdates', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime'
    )
    foreach ($v in $pauseValues) {
        Remove-RegValue -Path $RegPath_WU -Name $v
    }

    # --- Step 9: Trigger scan to pick up new policies ---
    try {
        Start-Process -FilePath 'usoclient' -ArgumentList 'StartScan' -NoNewWindow -Wait -ErrorAction Stop
        $changes += 'Triggered policy scan'
    }
    catch {
        # Non-fatal: scan will happen on next cycle
        $changes += 'Scan trigger skipped (UsoClient unavailable)'
    }

    # --- Done ---
    $summary = $changes -join '; '
    $msg = "REMEDIATED: WUfB configured. $summary"
    Write-Log $msg
    Write-Output $msg
    exit 0
}
catch {
    $msg = "ERROR: Remediation failed - $($_.Exception.Message)"
    Write-Log $msg
    Write-Output $msg
    exit 1
}
