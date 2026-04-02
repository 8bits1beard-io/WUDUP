#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Remediation Script - Removes all blockers so WUfB policy can fully manage the device.

.DESCRIPTION
    Intune Proactive Remediation script. Runs when WUDUP-Detect.ps1 reports
    non-compliant (device has settings blocking or conflicting with WUfB).

    Assumption: every device should be enrolled in Intune and receiving a
    WUfB Update Ring. Devices should NOT be managed by AD GPO, LGPO, or SCCM.

    This script removes ALL configuration that blocks, overrides, or conflicts
    with WUfB. It does NOT set update policies (deferrals, deadlines, version
    pins, etc.) -- those come from your Intune WUfB Update Ring assignment.

    Actions:
    1.  SCCM guard -- warns and exits if WU workload is not shifted to Intune
    2.  Stop WU-related services before making changes (prevents cached state)
    3.  Remove registry blockers (NoAutoUpdate, AUOptions, DisableWindowsUpdateAccess,
        DisableOSUpgrade, DoNotConnect, SetDisableUXWUAccess, NoWindowsUpdate)
    4.  Remove WSUS configuration (WUServer, WUStatusServer, UseWUServer, etc.)
    5.  Set PolicyDrivenSource keys to direct all update types to Windows Update
    6.  Remove stale pauses (policy-level and UX-level)
    7.  Remove legacy dual-scan artifacts (DeferUpgrade)
    8.  Remove conflicting GP/LGPO policy values from the WU and AU registry paths
    9.  Re-enable Windows Update services (wuauserv, UsoSvc, bits, cryptsvc,
        TrustedInstaller, dosvc) if set to Disabled
    10. Clear WU client internal policy cache (UpdatePolicy)
    11. Clear SoftwareDistribution folder (forces fresh scan state)
    12. Start services and trigger Intune re-sync + WU scan

    Exit 0 = Remediation succeeded
    Exit 1 = Remediation failed or skipped (SCCM)

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Remediation v2.0.0
    Created: 12 March 2026
    Updated: 1 April 2026
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

# Set $true to allow remediation even on SCCM-managed devices (with WU workload not shifted).
# Default: skip remediation if SCCM manages WU workload (changes will be overwritten).
$Config_AllowOnSCCM = $false

# ============================================================================
#  REGISTRY PATHS
# ============================================================================

$RegPath_WU      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$RegPath_UX      = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$RegPath_Explorer= 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$RegPath_WUPol   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate'

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
        $logFile  = Join-Path $logDir 'remediate.log'
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
    $hasSCCM     = ($null -ne $sccmService -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))

    if ($hasSCCM) {
        $coMgmtFlags       = Get-SafeRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
        $wuShiftedToIntune = ($null -ne $coMgmtFlags -and ($coMgmtFlags -band 16) -eq 16)

        if (-not $wuShiftedToIntune -and -not $Config_AllowOnSCCM) {
            $msg = Format-Output -Result 'SKIPPED' `
                -Reason 'SCCM/ConfigMgr manages WU workload -- local changes will be overwritten' `
                -Changes @("Set Config_AllowOnSCCM=`$true to override")
            Write-Log "SKIPPED: SCCM controls WU workload"
            Write-Output $msg
            exit 1
        }

        $changes += if ($wuShiftedToIntune) { 'SCCM co-managed (WU workload -> Intune)' }
                    else { 'WARNING: SCCM active, forced via Config_AllowOnSCCM' }
    }

    # --- Step 1: Stop WU-related services before making changes ---
    # Prevents cached in-memory state from overriding registry changes on restart.
    $stopServices = @('wuauserv', 'bits', 'UsoSvc')
    foreach ($svcName in $stopServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.Status -eq 'Running') {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        }
    }
    $changes += 'Stopped WU services (wuauserv, bits, UsoSvc)'

    # --- Step 2: Remove registry blockers ---
    # These values are already caught individually by the detection script.
    # Removing them re-enables update access and automatic update behavior.

    # GP path blockers
    $gpBlockers = @(
        @{ Path = $RegPath_WU; Name = 'DoNotConnectToWindowsUpdateInternetLocations' },
        @{ Path = $RegPath_WU; Name = 'SetDisableUXWUAccess' },
        @{ Path = $RegPath_WU; Name = 'DisableWindowsUpdateAccess' },
        @{ Path = $RegPath_WU; Name = 'DisableOSUpgrade' }
    )
    foreach ($item in $gpBlockers) {
        $current = Get-SafeRegistryValue -Path $item.Path -Name $item.Name
        if ($null -ne $current) {
            Remove-RegValue -Path $item.Path -Name $item.Name
            $changes += "Removed $($item.Name)"
        }
    }

    # AU subkey blockers (remove only when set to the blocking value)
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

    # Legacy policy paths
    $noWUExplorer = Get-SafeRegistryValue -Path $RegPath_Explorer -Name 'NoWindowsUpdate'
    if ($null -ne $noWUExplorer) {
        Remove-RegValue -Path $RegPath_Explorer -Name 'NoWindowsUpdate'
        $changes += 'Removed NoWindowsUpdate (Explorer policy path)'
    }

    $disableWUAltPath = Get-SafeRegistryValue -Path $RegPath_WUPol -Name 'DisableWindowsUpdateAccess'
    if ($null -ne $disableWUAltPath) {
        Remove-RegValue -Path $RegPath_WUPol -Name 'DisableWindowsUpdateAccess'
        $changes += 'Removed DisableWindowsUpdateAccess (legacy policy path)'
    }

    # --- Step 3: Remove WSUS configuration ---
    $wsusValues = @(
        @{ Path = $RegPath_WU; Name = 'WUServer' },
        @{ Path = $RegPath_WU; Name = 'WUStatusServer' },
        @{ Path = $RegPath_WU; Name = 'UpdateServiceUrlAlternate' },
        @{ Path = $RegPath_WU; Name = 'TargetGroup' },
        @{ Path = $RegPath_WU; Name = 'TargetGroupEnabled' },
        @{ Path = $RegPath_AU; Name = 'UseWUServer' }
    )
    foreach ($item in $wsusValues) {
        $current = Get-SafeRegistryValue -Path $item.Path -Name $item.Name
        if ($null -ne $current) {
            Remove-RegValue -Path $item.Path -Name $item.Name
            $changes += "Removed $($item.Name)"
        }
    }

    # --- Step 4: Set PolicyDrivenUpdateSource (Windows 10 2004+ / Windows 11) ---
    # Value 0 = Windows Update (WUfB). Must be set for all four update types.
    $sourceKeys = @(
        'SetPolicyDrivenUpdateSourceForFeatureUpdates',
        'SetPolicyDrivenUpdateSourceForQualityUpdates',
        'SetPolicyDrivenUpdateSourceForDriverUpdates',
        'SetPolicyDrivenUpdateSourceForOtherUpdates'
    )
    foreach ($key in $sourceKeys) {
        Set-RegDWord -Path $RegPath_WU -Name $key -Value 0
    }
    # UseUpdateClassPolicySource=1 is required for PolicyDrivenSource to take effect
    # when written via direct registry (not GPO/CSP). GPO and CSP set it automatically.
    Set-RegDWord -Path $RegPath_AU -Name 'UseUpdateClassPolicySource' -Value 1
    $changes += 'Set PolicyDrivenUpdateSource = 0 (WUfB) for all update types'

    # --- Step 5: Remove stale pauses ---
    # Policy-level pauses (GP path)
    $pauseValues = @(
        'PauseFeatureUpdates', 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
        'PauseQualityUpdates', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime'
    )
    $pauseRemoved = $false
    foreach ($v in $pauseValues) {
        $current = Get-SafeRegistryValue -Path $RegPath_WU -Name $v
        if ($null -ne $current) {
            Remove-RegValue -Path $RegPath_WU -Name $v
            $pauseRemoved = $true
        }
    }

    # UX-level pause (user-initiated via Settings app)
    $uxPauseValues = @('PauseUpdatesExpiryTime', 'PauseUpdatesStartTime')
    foreach ($v in $uxPauseValues) {
        $current = Get-SafeRegistryValue -Path $RegPath_UX -Name $v
        if ($null -ne $current) {
            Remove-RegValue -Path $RegPath_UX -Name $v
            $pauseRemoved = $true
        }
    }

    if ($pauseRemoved) { $changes += 'Removed stale pause entries (policy and UX paths)' }

    # --- Step 6: Remove legacy dual-scan artifacts ---
    $deferUpgrade = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DeferUpgrade'
    if ($null -ne $deferUpgrade) {
        Remove-RegValue -Path $RegPath_WU -Name 'DeferUpgrade'
        $changes += 'Removed DeferUpgrade (legacy dual-scan artifact)'
    }

    # --- Step 7: Remove conflicting GP/LGPO policy values ---
    # Enumerate all values in the WU and AU GP paths. Remove any values that are
    # NOT in the expected list. This clears LGPO/GPO settings that Intune cannot
    # override (MDMWinsOverGP does NOT apply to the Update Policy CSP).
    #
    # Values to KEEP (set by remediation or valid WUfB configuration):
    $keepWUValues = @(
        # Scan source keys (set by this script)
        'SetPolicyDrivenUpdateSourceForFeatureUpdates',
        'SetPolicyDrivenUpdateSourceForQualityUpdates',
        'SetPolicyDrivenUpdateSourceForDriverUpdates',
        'SetPolicyDrivenUpdateSourceForOtherUpdates',
        # WUfB policy values (may be set by GPO or Intune Settings Catalog; keep them)
        'DeferFeatureUpdatesPeriodInDays',
        'DeferQualityUpdatesPeriodInDays',
        'TargetReleaseVersion',
        'TargetReleaseVersionInfo',
        'ProductVersion',
        'BranchReadinessLevel',
        'ManagePreviewBuilds',
        'ExcludeWUDriversInQualityUpdate',
        'ConfigureDeadlineForFeatureUpdates',
        'ConfigureDeadlineForQualityUpdates',
        'ConfigureDeadlineGracePeriod',
        'ConfigureDeadlineGracePeriodForFeatureUpdates',
        'ComplianceDeadlineForFU',
        'ComplianceDeadline',
        'ComplianceGracePeriod',
        'ComplianceGracePeriodForFU',
        'DisableDualScan'
    )

    $keepAUValues = @(
        # Set by this script
        'UseUpdateClassPolicySource',
        # Standard AU scheduling values; keep if present (non-blocking)
        'AutoInstallMinorUpdates',
        'DetectionFrequency',
        'DetectionFrequencyEnabled',
        'ScheduledInstallDay',
        'ScheduledInstallTime',
        'ScheduledInstallEveryWeek',
        'ScheduledInstallFirstWeek',
        'ScheduledInstallSecondWeek',
        'ScheduledInstallThirdWeek',
        'ScheduledInstallFourthWeek',
        'AlwaysAutoRebootAtScheduledTime',
        'AlwaysAutoRebootAtScheduledTimeMinutes'
    )

    $gpRemovedCount = 0

    if (Test-Path $RegPath_WU) {
        try {
            $wuProps = Get-ItemProperty -Path $RegPath_WU -ErrorAction Stop
            $wuProps.PSObject.Properties |
                Where-Object { $_.Name -notlike 'PS*' } |
                ForEach-Object {
                    if ($_.Name -notin $keepWUValues) {
                        Remove-RegValue -Path $RegPath_WU -Name $_.Name
                        $gpRemovedCount++
                        Write-Log "Removed GP conflict: WU\$($_.Name) = $($_.Value)"
                    }
                }
        }
        catch { }
    }

    if (Test-Path $RegPath_AU) {
        try {
            $auProps = Get-ItemProperty -Path $RegPath_AU -ErrorAction Stop
            $auProps.PSObject.Properties |
                Where-Object { $_.Name -notlike 'PS*' } |
                ForEach-Object {
                    if ($_.Name -notin $keepAUValues) {
                        Remove-RegValue -Path $RegPath_AU -Name $_.Name
                        $gpRemovedCount++
                        Write-Log "Removed GP conflict: AU\$($_.Name) = $($_.Value)"
                    }
                }
        }
        catch { }
    }

    if ($gpRemovedCount -gt 0) {
        $changes += "Removed $gpRemovedCount conflicting GP/LGPO value(s) from WU policy paths"
    }

    # --- Step 8: Re-enable services that must not be Disabled ---
    # wuauserv and UsoSvc are critical; also re-enable additional WU infrastructure services.
    $requiredServices = @(
        @{ Name = 'wuauserv';        Display = 'Windows Update' },
        @{ Name = 'UsoSvc';          Display = 'Update Orchestrator' },
        @{ Name = 'WaaSMedicSvc';    Display = 'Windows Update Medic' },
        @{ Name = 'bits';            Display = 'Background Intelligent Transfer' },
        @{ Name = 'cryptsvc';        Display = 'Cryptographic Services' },
        @{ Name = 'TrustedInstaller';Display = 'Windows Modules Installer' },
        @{ Name = 'dosvc';           Display = 'Delivery Optimization' }
    )
    foreach ($svcDef in $requiredServices) {
        $svc = Get-Service -Name $svcDef.Name -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.StartType -eq 'Disabled') {
            Set-Service -Name $svcDef.Name -StartupType Manual -ErrorAction SilentlyContinue
            $changes += "Re-enabled $($svcDef.Name) service ($($svcDef.Display)) -- was Disabled"
        }
    }

    # --- Step 9: Clear WU client internal policy cache ---
    # The UpdatePolicy tree stores the WU client's resolved policy state. Stale
    # entries here cause the client to ignore fresh registry changes. Intune
    # re-sync (triggered below) will rebuild this tree with correct values.
    $updatePolicyPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy'
    if (Test-Path $updatePolicyPath) {
        Remove-Item -Path $updatePolicyPath -Recurse -Force -ErrorAction SilentlyContinue
        $changes += 'Cleared UpdatePolicy cache'
    }

    # --- Step 10: Clear SoftwareDistribution folder ---
    # Forces a fresh WU scan state and rebuilds the WU client database.
    # Services must be stopped first (Step 1) or files will be locked.
    $sdPath = "$env:SystemRoot\SoftwareDistribution"
    if (Test-Path $sdPath) {
        Remove-Item -Path $sdPath -Recurse -Force -ErrorAction SilentlyContinue
        $changes += 'Cleared SoftwareDistribution (fresh scan state)'
    }

    # --- Step 11: Start services and trigger re-sync ---
    foreach ($svcName in $stopServices) {
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
    }
    $changes += 'Started WU services'

    # Trigger Intune to re-deliver policies (rebuilds PolicyManager and UpdatePolicy entries)
    $pushTask = Get-ScheduledTask -TaskName 'PushLaunch' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pushTask) {
        Start-ScheduledTask -TaskName $pushTask.TaskName -TaskPath $pushTask.TaskPath -ErrorAction SilentlyContinue
        $changes += 'Triggered Intune policy re-sync (PushLaunch)'
    }

    # Trigger WU scan so the device picks up updates immediately
    try {
        Start-Process -FilePath 'usoclient' -ArgumentList 'StartScan' -NoNewWindow -Wait -ErrorAction Stop
        $changes += 'Triggered WU scan (usoclient StartScan)'
    }
    catch {
        $changes += 'WU scan trigger skipped (usoclient unavailable)'
    }

    # --- Done ---
    $msg = Format-Output -Result 'REMEDIATED' `
        -Reason 'All blockers and conflicts removed -- device ready for WUfB policy' `
        -Changes $changes
    Write-Log "REMEDIATED: $($changes -join '; ')"
    Write-Output $msg
    exit 0
}
catch {
    $msg = Format-Output -Result 'ERROR' -Reason "Remediation failed -- $($_.Exception.Message)"
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output $msg
    exit 1
}
