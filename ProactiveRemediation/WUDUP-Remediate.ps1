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
    2. Stops WU-related services (wuauserv, bits, usosvc) to prevent cached state
    3. Removes WSUS configuration (WUServer, WUStatusServer, UseWUServer, etc.)
    4. Sets PolicyDrivenUpdateSource keys to direct all updates to Windows Update
    5. Removes NoAutoUpdate and AUOptions=1 if set (re-enables automatic updates)
    6. Cleans stale pause entries
    7. Clears WU client internal policy cache (UpdatePolicy)
    8. Clears SoftwareDistribution folder (forces fresh scan state)
    9. Re-enables Windows Update (wuauserv) and Update Orchestrator (UsoSvc) services if disabled
    10. Starts services and triggers Intune re-sync + WU scan

    Exit 0 = Remediation succeeded
    Exit 1 = Remediation failed

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Remediation v2.0.0
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

function Format-Output {
    param(
        [string]$Result,       # REMEDIATED / SKIPPED / ERROR
        [string]$Reason,       # One-line summary
        [string[]]$Changes     # List of actions taken
    )
    $lines = @()
    $lines += "=== WUDUP Remediation ==="
    $lines += "$Result"
    $lines += ""
    $lines += "Reason: $Reason"
    if ($Changes -and $Changes.Count -gt 0) {
        $lines += ""
        $lines += "Actions:"
        foreach ($c in $Changes) { $lines += "  - $c" }
    }
    return ($lines -join "`n")
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
            $msg = Format-Output -Result 'SKIPPED' `
                -Reason "SCCM/ConfigMgr manages WU workload — local changes will be overwritten" `
                -Changes @("Set Config_AllowOnSCCM=`$true to override")
            Write-Log "SKIPPED: SCCM controls WU workload"
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

    # --- Step 0b: Check for MDM-delivered blockers that remediation cannot fix ---
    $mdmPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $mdmAllowAutoUpdate = Get-SafeRegistryValue -Path $mdmPath -Name 'AllowAutoUpdate'
    if ($mdmAllowAutoUpdate -eq 5) {
        $changes += 'WARNING: MDM AllowAutoUpdate=5 — auto updates disabled via Intune, review device config profiles'
    }
    $mdmAllowUpdateService = Get-SafeRegistryValue -Path $mdmPath -Name 'AllowUpdateService'
    if ($mdmAllowUpdateService -eq 0) {
        $changes += 'WARNING: MDM AllowUpdateService=0 — all update services blocked via Intune, review device config profiles'
    }

    # --- Step 1: Stop WU-related services before making changes ---
    # Prevents cached in-memory state from overriding registry changes
    $stopServices = @('wuauserv', 'bits', 'UsoSvc')
    foreach ($svcName in $stopServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq 'Running') {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        }
    }
    $changes += 'Stopped WU services'

    # --- Step 2: Remove WSUS configuration ---
    $wsusValues = @(
        @{ Path = $RegPath_WU; Name = 'WUServer' },
        @{ Path = $RegPath_WU; Name = 'WUStatusServer' },
        @{ Path = $RegPath_WU; Name = 'DoNotConnectToWindowsUpdateInternetLocations' },
        @{ Path = $RegPath_WU; Name = 'SetDisableUXWUAccess' },
        @{ Path = $RegPath_WU; Name = 'DisableWindowsUpdateAccess' },
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

    # --- Step 3: Set PolicyDrivenUpdateSource (Windows 10 2004+ / Windows 11) ---
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

    # --- Step 4: Remove update-disabling registry values ---
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

    # --- Step 5: Clean up stale pause entries ---
    $pauseValues = @(
        'PauseFeatureUpdates', 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
        'PauseQualityUpdates', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime'
    )
    foreach ($v in $pauseValues) {
        Remove-RegValue -Path $RegPath_WU -Name $v
    }

    # --- Step 6: Clear WU client internal policy cache ---
    # The UpdatePolicy path stores the WU client's resolved policy state. Stale entries
    # here cause the client to ignore registry policy changes. Intune re-sync rebuilds it.
    $updatePolicyPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy'
    if (Test-Path $updatePolicyPath) {
        Remove-Item -Path $updatePolicyPath -Recurse -Force -ErrorAction SilentlyContinue
        $changes += 'Cleared UpdatePolicy cache'
    }

    # --- Step 7: Clear SoftwareDistribution folder ---
    # Forces a fresh scan state and rebuilds the WU client database. Services must be
    # stopped first (Step 1) or files will be locked.
    $sdPath = "$env:SystemRoot\SoftwareDistribution"
    if (Test-Path $sdPath) {
        Remove-Item -Path $sdPath -Recurse -Force -ErrorAction SilentlyContinue
        $changes += 'Cleared SoftwareDistribution'
    }

    # --- Step 8: Re-enable Windows Update services if disabled ---
    $svcNames = @('wuauserv', 'UsoSvc')
    foreach ($svcName in $svcNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.StartType -eq 'Disabled') {
            Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue
            $changes += "Re-enabled $svcName service (was Disabled)"
        }
    }

    # --- Step 9: Start services and trigger policy re-sync ---
    # Start services back up so they read fresh registry state
    foreach ($svcName in $stopServices) {
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
    }
    $changes += 'Started WU services'

    # Trigger Intune to re-deliver policies (rebuilds PolicyManager entries)
    $pushTask = Get-ScheduledTask -TaskName 'PushLaunch' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pushTask) {
        Start-ScheduledTask -TaskName $pushTask.TaskName -TaskPath $pushTask.TaskPath -ErrorAction SilentlyContinue
        $changes += 'Triggered Intune policy re-sync (PushLaunch)'
    }

    # Trigger WU scan via usoclient
    try {
        Start-Process -FilePath 'usoclient' -ArgumentList 'StartScan' -NoNewWindow -Wait -ErrorAction Stop
        $changes += 'Triggered WU scan'
    }
    catch {
        $changes += 'WU scan trigger skipped (UsoClient unavailable)'
    }

    # --- Done ---
    $msg = Format-Output -Result 'REMEDIATED' `
        -Reason "Blockers removed, WU state reset — device ready for WUfB policy" `
        -Changes $changes
    Write-Log "REMEDIATED: $($changes -join '; ')"
    Write-Output $msg
    exit 0
}
catch {
    $msg = Format-Output -Result 'ERROR' -Reason "Remediation failed — $($_.Exception.Message)"
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output $msg
    exit 1
}
