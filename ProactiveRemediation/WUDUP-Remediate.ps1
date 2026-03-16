#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Remediation Script - Removes blockers so WUfB policy can take effect.

.DESCRIPTION
    Intune Proactive Remediation script. Runs when WUDUP-Detect.ps1 reports
    non-compliant (device not managed by WUfB).

    This script only removes configuration that blocks WUfB from managing the
    device. It does NOT set update policies (deferrals, deadlines, version pins,
    etc.) — those should come from your Intune WUfB Update Ring assignment.

    Actions:
    1. Checks for SCCM — warns and exits if WU workload is not shifted
    2. Removes WSUS configuration (WUServer, WUStatusServer, UseWUServer, etc.)
    3. Sets PolicyDrivenUpdateSource keys to direct all updates to Windows Update
    4. Removes NoAutoUpdate and AUOptions=1 if set (re-enables automatic updates)
    5. Cleans stale pause entries
    6. Re-enables Windows Update (wuauserv) and Update Orchestrator (UsoSvc) services if disabled
    7. Triggers policy scan for immediate pickup

    Exit 0 = Remediation succeeded
    Exit 1 = Remediation failed

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Remediation v1.5.0
    Created: 12 March 2026
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

# SCCM behavior: set to $true to allow remediation even on SCCM-managed devices
$Config_AllowOnSCCM = $false   # $false = skip remediation if SCCM manages WU workload

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

    # --- Step 3: Remove update-disabling registry values ---
    $noAutoUpdate = Get-SafeRegistryValue -Path $RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdate -eq 1) {
        Remove-RegValue -Path $RegPath_AU -Name 'NoAutoUpdate'
        $changes += 'Removed NoAutoUpdate=1'
    }

    $auOptions = Get-SafeRegistryValue -Path $RegPath_AU -Name 'AUOptions'
    if ($auOptions -eq 1) {
        Remove-RegValue -Path $RegPath_AU -Name 'AUOptions'
        $changes += 'Removed AUOptions=1 (Never check)'
    }

    # --- Step 4: Clean up stale pause entries ---
    $pauseValues = @(
        'PauseFeatureUpdates', 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
        'PauseQualityUpdates', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime'
    )
    foreach ($v in $pauseValues) {
        Remove-RegValue -Path $RegPath_WU -Name $v
    }

    # --- Step 5: Re-enable Windows Update services if disabled ---
    $svcNames = @('wuauserv', 'UsoSvc')
    foreach ($svcName in $svcNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.StartType -eq 'Disabled') {
            Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue
            $changes += "Re-enabled $svcName service (was Disabled)"
        }
    }

    # --- Step 6: Trigger scan to pick up new policies ---
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
    $msg = "REMEDIATED: Blockers removed, device ready for WUfB policy. $summary"
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
