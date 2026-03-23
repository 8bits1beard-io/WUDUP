#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Detection Script - Checks if device is managed by Windows Update for Business.

.DESCRIPTION
    Intune Proactive Remediation detection script.
    Determines whether the device's update infrastructure is correctly
    configured for WUfB to manage updates (compliant) or whether something
    is blocking or overriding WUfB (non-compliant, triggers remediation).

    Core question: "Does this device have all the necessary settings so
    that Intune WUfB can manage ALL updates?"

    Primary compliance gates (evaluated in order):
    1. No update blockers:
       - NoAutoUpdate=1 or AUOptions=1 (automatic updates disabled)
       - DoNotConnectToWindowsUpdateInternetLocations=1 (WU connectivity blocked)
       - SetDisableUXWUAccess=1 (WU UI/access disabled)
       - Windows Update (wuauserv) or Update Orchestrator (UsoSvc) services disabled
    2. No SCCM controlling updates (unless co-mgmt WU workload shifted to Intune)
    3. All four PolicyDrivenSource keys set to 0 (WU) — Feature, Quality,
       Driver, Other. These are required regardless of WSUS presence. Missing
       or wrong-valued keys are non-compliant.

    Secondary gates — is the device actually receiving WUfB policy?
    - Intune WUfB Update Ring actively delivering policy ($Config_RequireUpdateRing)
    - Active MDM enrollment ($Config_RequireMDMEnrollment)
    - Recent Windows Update scan activity ($Config_MaxScanAgeDays)

    WUfB policy indicators (deferrals, deadlines, version targeting, etc.)
    are collected for informational output but are NOT compliance gates —
    those settings come from the Intune Update Ring.

    Exit 0 = Infrastructure correct and device receiving policy (compliant)
    Exit 1 = Infrastructure wrong or device not receiving policy (non-compliant)

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Detection v1.6.0
    Created: 12 March 2026
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

# Update Ring enforcement: requires an Intune WUfB Update Ring to be actively
# delivering policy. Devices with only remediation-set PolicyDrivenSource keys
# (no actual Update Ring) will report non-compliant. Set to $false if you only
# need to verify the device is pointed at WU, not that an Update Ring is assigned.
$Config_RequireUpdateRing = $true

# MDM enrollment enforcement: requires an active Intune MDM enrollment
# (EnrollmentState=1). Devices without a healthy enrollment cannot receive
# WUfB policy from Intune. Remediation cannot fix this — manual re-enrollment
# is needed. Set to $false if devices may receive WUfB policy via GPO instead.
$Config_RequireMDMEnrollment = $true

# Maximum days since last successful Windows Update scan before flagging
# non-compliant. When the WU client hasn't scanned within this window, the
# device may not be receiving updates even if configured correctly. Remediation
# cannot fix stale scans — manual investigation is needed. Set to 0 to disable.
$Config_MaxScanAgeDays = 7

# ============================================================================
#  REGISTRY PATHS
# ============================================================================

$RegPath_WU  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$RegPath_MDM = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'

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

function Write-Log {
    param([string]$Message)
    try {
        $logDir = Join-Path $env:ProgramData 'WUDUP\Logs'
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $logFile = Join-Path $logDir 'detect.log'
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -Path $logFile -Value "[$timestamp] $Message" -ErrorAction SilentlyContinue
    }
    catch { }
}

# Builds structured multi-line output for Intune portal display.
# Intune only uses the exit code for compliance; this text is for admins.
function Format-Output {
    param(
        [string]$Result,           # COMPLIANT / NON-COMPLIANT / ERROR
        [string]$Reason,           # One-line summary of why
        [string[]]$Details,        # Additional detail lines
        [string[]]$UpdateSource,   # Update source status lines
        [string[]]$Policy,         # WUfB policy lines
        [string[]]$Health          # Health check lines
    )
    $lines = @()
    $lines += "=== WUDUP Detection ==="
    $lines += "$Result — $Reason"

    if ($UpdateSource -and $UpdateSource.Count -gt 0) {
        $lines += ""
        $lines += "Update Source:"
        $lines += $UpdateSource
    }

    if ($Details -and $Details.Count -gt 0) {
        $lines += ""
        foreach ($d in $Details) { $lines += $d }
    }

    if ($Health -and $Health.Count -gt 0) {
        $lines += ""
        $lines += "Management Channel:"
        foreach ($h in $Health) { $lines += "  $h" }
    }

    if ($Policy -and $Policy.Count -gt 0) {
        $lines += ""
        $lines += "Applied WUfB Policy:"
        foreach ($p in $Policy) { $lines += "  $p" }
    }

    return ($lines -join "`n")
}

# Reads a value from GP path first, then MDM path as fallback
function Get-PolicyValue {
    param([string]$Name)
    $val = Get-SafeRegistryValue -Path $RegPath_WU -Name $Name
    if ($null -ne $val) { return $val }
    return Get-SafeRegistryValue -Path $RegPath_MDM -Name $Name
}

# MDM provider IDs that deliver WUfB policy. 'MS DM Server' = direct Intune
# enrollment. 'WMI_Bridge_SCCM_Server' = SCCM co-management bridge (policies
# delivered via Intune through the co-management channel).
$MDMProviderIDs = @('MS DM Server', 'WMI_Bridge_SCCM_Server')

# Checks whether an active MDM enrollment is delivering WUfB Update policy.
# Looks in PolicyManager\Providers\<EnrollmentGUID>\default\device\Update for
# WUfB-specific values (deferrals, deadlines, version targeting) that indicate
# an Update Ring assignment — not just PolicyDrivenSource keys from remediation.
# Recognizes both direct Intune and SCCM co-management bridge enrollments.
function Test-IntuneUpdateRingDelivered {
    $enrollPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path $enrollPath)) { return $false }

    $wufbValueNames = @(
        'DeferFeatureUpdatesPeriodInDays',
        'DeferQualityUpdatesPeriodInDays',
        'ConfigureDeadlineForFeatureUpdates',
        'ConfigureDeadlineForQualityUpdates',
        'ConfigureDeadlineGracePeriod',
        'ConfigureDeadlineGracePeriodForFeatureUpdates',
        'TargetReleaseVersion',
        'TargetReleaseVersionInfo',
        'ProductVersion',
        'BranchReadinessLevel',
        'ExcludeWUDriversInQualityUpdate',
        'ManagePreviewBuilds'
    )

    $enrollments = Get-ChildItem -Path $enrollPath -ErrorAction SilentlyContinue
    foreach ($enrollment in $enrollments) {
        $providerID = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'ProviderID'
        if ($providerID -notin $MDMProviderIDs) { continue }

        $guid = $enrollment.PSChildName
        $mdmUpdatePath = "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$guid\default\device\Update"
        if (-not (Test-Path $mdmUpdatePath)) { continue }

        foreach ($valName in $wufbValueNames) {
            $val = Get-SafeRegistryValue -Path $mdmUpdatePath -Name $valName
            if ($null -ne $val) { return $true }
        }
    }

    return $false
}

# Checks for a healthy MDM enrollment (Intune or co-management bridge).
# Returns a hashtable with:
#   Enrolled  = $true/$false   — whether an active MDM enrollment exists
#   UPN       = string|$null   — the enrolled user's UPN (if found)
#   GUID      = string|$null   — the enrollment GUID
#   Provider  = string|$null   — the ProviderID (e.g. 'MS DM Server' or 'WMI_Bridge_SCCM_Server')
function Test-MDMEnrollmentHealth {
    $result = @{ Enrolled = $false; UPN = $null; GUID = $null; Provider = $null }
    $enrollPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path $enrollPath)) { return $result }

    $enrollments = Get-ChildItem -Path $enrollPath -ErrorAction SilentlyContinue
    foreach ($enrollment in $enrollments) {
        $providerID = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'ProviderID'
        if ($providerID -notin $MDMProviderIDs) { continue }

        $enrollState = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'EnrollmentState'
        # EnrollmentState 1 = enrolled and active
        if ($enrollState -ne 1) { continue }

        $result.Enrolled = $true
        $result.UPN = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'UPN'
        $result.GUID = $enrollment.PSChildName
        $result.Provider = $providerID
        return $result
    }

    return $result
}

# Checks when the Windows Update client last had activity.
# Uses COM Microsoft.Update.Session history (reliable on modern Windows)
# with fallback to legacy Auto Update registry path.
# Returns a hashtable with:
#   LastScan  = [DateTime]|$null  — timestamp of last WU activity
#   AgeDays   = [int]|$null       — days since last activity
function Get-LastWUScanStatus {
    $result = @{ LastScan = $null; AgeDays = $null }

    # Primary: COM update history — works regardless of which service triggered the scan
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $latest = $searcher.QueryHistory(0, 1)
            if ($null -ne $latest -and $latest.Count -gt 0 -and $latest.Item(0).Date -gt [DateTime]::MinValue) {
                $result.LastScan = $latest.Item(0).Date
                $result.AgeDays = [math]::Floor(((Get-Date) - $result.LastScan).TotalDays)
                return $result
            }
        }
    }
    catch { }

    # Fallback: legacy Auto Update registry path (may be stale on modern Windows)
    $detectPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
    $lastSuccess = Get-SafeRegistryValue -Path $detectPath -Name 'LastSuccessTime'
    if ($null -ne $lastSuccess) {
        try {
            $scanTime = [DateTime]::Parse($lastSuccess)
            $result.LastScan = $scanTime
            $result.AgeDays = [math]::Floor(((Get-Date) - $scanTime).TotalDays)
        }
        catch { }
    }

    return $result
}

# ============================================================================
#  DETECTION LOGIC
# ============================================================================

try {
    Write-Log "Detection started"
    $indicators = @()

    # --- 1. Policy-Driven Update Source (most definitive, Windows 10 2004+) ---
    # Check all 4 types: Feature, Quality, Driver, Other
    $srcFeature = Get-PolicyValue -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality = Get-PolicyValue -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcDriver  = Get-PolicyValue -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcOther   = Get-PolicyValue -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'

    # Value 0 = Windows Update (WUfB), Value 1 = WSUS
    $featureFromWU = ($srcFeature -eq 0)
    $qualityFromWU = ($srcQuality -eq 0)
    $driverFromWU  = ($srcDriver -eq 0)
    $otherFromWU   = ($srcOther -eq 0)

    # Build update source status lines for output
    $pdsStatus = @(
        "  Feature updates sourced from:  $(if ($featureFromWU) { 'WUfB' } elseif ($null -eq $srcFeature) { 'NOT CONFIGURED' } else { 'WSUS' })"
        "  Quality updates sourced from:  $(if ($qualityFromWU) { 'WUfB' } elseif ($null -eq $srcQuality) { 'NOT CONFIGURED' } else { 'WSUS' })"
        "  Driver updates sourced from:   $(if ($driverFromWU)  { 'WUfB' } elseif ($null -eq $srcDriver)  { 'NOT CONFIGURED' } else { 'WSUS' })"
        "  Other updates sourced from:    $(if ($otherFromWU)   { 'WUfB' } elseif ($null -eq $srcOther)   { 'NOT CONFIGURED' } else { 'WSUS' })"
    )

    # PolicyDrivenSource status is shown in its own section — not duplicated in indicators

    # --- 2. Deferral Policies ---
    $featureDefer = Get-PolicyValue -Name 'DeferFeatureUpdatesPeriodInDays'
    $qualityDefer = Get-PolicyValue -Name 'DeferQualityUpdatesPeriodInDays'

    if ($null -ne $featureDefer -and $featureDefer -gt 0) { $indicators += "Feature deferral:       $featureDefer days" }
    if ($null -ne $qualityDefer -and $qualityDefer -gt 0) { $indicators += "Quality deferral:       $qualityDefer days" }

    # --- 3. Version Targeting ---
    # GP path: TargetReleaseVersion=1 (DWORD enable flag) + TargetReleaseVersionInfo="24H2" (REG_SZ)
    # MDM path: TargetReleaseVersion="24H2" (the version string itself, not a boolean)
    $targetEnabled = Get-PolicyValue -Name 'TargetReleaseVersion'
    $targetVersion = Get-PolicyValue -Name 'TargetReleaseVersionInfo'
    $productVersion = Get-PolicyValue -Name 'ProductVersion'

    $versionDisplay = $null
    if ($targetEnabled -eq 1 -and $null -ne $targetVersion) {
        # GP-style: enable flag + separate version string
        $versionDisplay = ($productVersion, $targetVersion | Where-Object { $_ }) -join ' '
    }
    elseif ($null -ne $targetEnabled -and $targetEnabled -ne 0 -and $targetEnabled -ne 1) {
        # MDM-style: TargetReleaseVersion IS the version string (e.g. "24H2")
        $versionDisplay = ($productVersion, $targetEnabled | Where-Object { $_ }) -join ' '
    }
    if ($versionDisplay) { $indicators += "Version target:         $versionDisplay" }

    # --- 4. Compliance Deadlines ---
    # GP writes native names (ComplianceDeadlineForFU, ComplianceDeadline); MDM uses Configure* names
    $deadlineFeature = Get-PolicyValue -Name 'ConfigureDeadlineForFeatureUpdates'
    if ($null -eq $deadlineFeature) {
        $deadlineFeature = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceDeadlineForFU'
    }
    $deadlineQuality = Get-PolicyValue -Name 'ConfigureDeadlineForQualityUpdates'
    if ($null -eq $deadlineQuality) {
        $deadlineQuality = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceDeadline'
    }
    $deadlineGrace   = Get-PolicyValue -Name 'ConfigureDeadlineGracePeriod'
    if ($null -eq $deadlineGrace) {
        $deadlineGrace = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceGracePeriod'
    }
    $deadlineGraceFU = Get-PolicyValue -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates'
    if ($null -eq $deadlineGraceFU) {
        $deadlineGraceFU = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceGracePeriodForFU'
    }

    if ($null -ne $deadlineFeature) { $indicators += "Feature deadline:       $deadlineFeature days" }
    if ($null -ne $deadlineQuality) { $indicators += "Quality deadline:       $deadlineQuality days" }
    if ($null -ne $deadlineGrace)   { $indicators += "Grace period:           $deadlineGrace days" }
    if ($null -ne $deadlineGraceFU) { $indicators += "Grace period (feature): $deadlineGraceFU days" }

    # --- 5. Channel / Preview Build Management ---
    $branchLevel = Get-PolicyValue -Name 'BranchReadinessLevel'
    $previewBuilds = Get-PolicyValue -Name 'ManagePreviewBuilds'

    # BranchReadinessLevel: 2=GA, 4=Preview, 8=Insider Slow, 16=Semi-Annual Channel
    if ($null -ne $branchLevel) {
        $branchName = switch ($branchLevel) {
            2  { 'General Availability' }
            4  { 'Preview' }
            8  { 'Insider Slow' }
            16 { 'Semi-Annual Channel' }
            default { "Channel $branchLevel" }
        }
        $indicators += "Update channel:         $branchName"
    }
    # ManagePreviewBuilds: 0=Disabled, 1=Disabled, 2=Enabled
    if ($null -ne $previewBuilds) {
        $previewName = if ($previewBuilds -eq 2) { 'Enabled' } else { 'Disabled' }
        $indicators += "Preview builds:         $previewName"
    }

    # --- 6. Driver Exclusion ---
    $excludeDrivers = Get-PolicyValue -Name 'ExcludeWUDriversInQualityUpdate'
    if ($null -ne $excludeDrivers) {
        $driverName = if ($excludeDrivers -eq 1) { 'Excluded from quality updates' } else { 'Included in quality updates' }
        $indicators += "Driver updates:         $driverName"
    }

    # --- 7. Update Blocker Checks ---
    $blockers = @()

    # NoAutoUpdate=1 disables all automatic updates
    $noAutoUpdate = Get-SafeRegistryValue -Path $RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdate -eq 1) { $blockers += 'Automatic updates disabled (NoAutoUpdate=1)' }

    # AUOptions=1 means "Never check for updates" — effectively disables WU
    $auOptions = Get-SafeRegistryValue -Path $RegPath_AU -Name 'AUOptions'
    if ($auOptions -eq 1) { $blockers += 'Set to never check for updates (AUOptions=1)' }

    # DoNotConnectToWindowsUpdateInternetLocations=1 blocks WU server connectivity
    $noConnect = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    if ($noConnect -eq 1) { $blockers += 'Windows Update internet connectivity blocked' }

    # SetDisableUXWUAccess=1 hides WU UI and can block update flows
    $disableUX = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetDisableUXWUAccess'
    if ($disableUX -eq 1) { $blockers += 'Windows Update UI/access disabled' }

    # Windows Update service (wuauserv) must not be disabled
    $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') { $blockers += 'Windows Update service (wuauserv) is disabled' }

    # Update Orchestrator Service (UsoSvc) must not be disabled
    $usoSvc = Get-Service -Name 'UsoSvc' -ErrorAction SilentlyContinue
    if ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') { $blockers += 'Update Orchestrator service (UsoSvc) is disabled' }

    $hasBlockers = ($blockers.Count -gt 0)

    # --- 8. WSUS Configuration ---
    $wuServer       = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUServer'
    $wuStatusServer = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUStatusServer'
    $useWUServer    = Get-SafeRegistryValue -Path $RegPath_AU -Name 'UseWUServer'
    $hasWSUS        = ($useWUServer -eq 1 -and $null -ne $wuServer)

    # --- 9. Dual-Scan Suppression ---
    $disableDualScan = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DisableDualScan'

    # --- 10. SCCM Detection ---
    $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
    $hasSCCM     = ($null -ne $sccmService -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))

    # Check co-management: if the WU workload is shifted to Intune (CoManagementFlags bit 16),
    # SCCM no longer controls updates — evaluate as Intune-managed instead.
    # Mirrors the co-management check in WUDUP-Remediate.ps1.
    $wuShiftedToIntune = $false
    if ($hasSCCM) {
        $coMgmtFlags = Get-SafeRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
        $wuShiftedToIntune = ($null -ne $coMgmtFlags -and ($coMgmtFlags -band 16) -eq 16)
        if ($wuShiftedToIntune) {
            $hasSCCM = $false
        }
    }

    # ========================================================================
    #  EVALUATE COMPLIANCE
    # ========================================================================
    #  Core question: "Does this device have all the necessary settings so
    #  that Intune WUfB can manage ALL updates?"
    #
    #  Primary compliance: the 4 PolicyDrivenSource keys must ALL be set to 0,
    #  no blockers, no SCCM/WSUS overriding. These are the infrastructure
    #  settings that make WUfB win.
    #
    #  Secondary: is the device actually receiving WUfB policy from Intune?
    #  (Update Ring delivery, MDM enrollment, scan freshness)
    #
    #  WUfB policy indicators (deferrals, deadlines, etc.) are informational
    #  output only — they come from the Update Ring, not from this script.
    # ========================================================================

    $hasWUfBIndicators = ($indicators.Count -gt 0)
    $allPolicyDrivenToWU = ($featureFromWU -and $qualityFromWU -and $driverFromWU -and $otherFromWU)

    # --- Gate 1: Blockers prevent WUfB from functioning ---
    if ($hasBlockers) {
        $msg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason "Update blockers detected — WUfB cannot function on this device" `
            -Details ($blockers | ForEach-Object { "  - $_" }) `
            -UpdateSource $pdsStatus `
            -Policy $indicators
        Write-Log ($blockers -join '; ')
        Write-Output $msg
        exit 1
    }

    # --- Gate 2: SCCM controlling updates (without co-mgmt WU shift) ---
    if ($hasSCCM) {
        $msg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason "SCCM/ConfigMgr is managing updates (WU workload not shifted to Intune)" `
            -UpdateSource $pdsStatus `
            -Policy $indicators
        Write-Log "SCCM controls WU workload"
        Write-Output $msg
        exit 1
    }

    # --- Gate 3: All four update types must be sourced from WUfB ---
    if (-not $allPolicyDrivenToWU) {
        $problemLines = @()
        foreach ($type in @('Feature','Quality','Driver','Other')) {
            $val = Get-Variable -Name "src$type" -ValueOnly
            if ($null -eq $val) {
                $problemLines += "  - $type updates: not configured to use WUfB"
            }
            elseif ($val -ne 0) {
                $problemLines += "  - $type updates: directed to WSUS instead of WUfB"
            }
        }
        $reason = "Not all update types are sourced from WUfB"
        if ($hasWSUS) { $reason += " — WSUS ($wuServer) will control the misconfigured types" }
        $msg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason $reason `
            -Details $problemLines `
            -UpdateSource $pdsStatus `
            -Policy $indicators
        Write-Log "Update source incomplete: $($problemLines -join '; ')"
        Write-Output $msg
        exit 1
    }

    # --- Primary compliance passed: all infrastructure settings are correct ---
    # Now check secondary gates: is the device actually receiving WUfB policy?

    $hasUpdateRing = Test-IntuneUpdateRingDelivered
    $healthLines = @()

    if (-not $hasUpdateRing -and $Config_RequireUpdateRing) {
        $msg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason "Device is configured for WUfB but no Intune Update Ring is delivering policy" `
            -Details @("  Action: Assign a WUfB Update Ring to this device in Intune") `
            -UpdateSource $pdsStatus `
            -Policy $indicators
        Write-Log "No Update Ring policy detected"
        Write-Output $msg
        exit 1
    }
    $healthLines += "Update Ring:    $(if ($hasUpdateRing) { 'Active' } else { 'Not detected' })"

    # MDM enrollment health
    $mdmHealth = Test-MDMEnrollmentHealth
    if ($Config_RequireMDMEnrollment -and -not $mdmHealth.Enrolled) {
        $msg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason "Device has no active Intune MDM enrollment — cannot receive WUfB policy" `
            -Details @("  Action: Re-enroll this device in Intune") `
            -UpdateSource $pdsStatus `
            -Policy $indicators
        Write-Log "No active MDM enrollment"
        Write-Output $msg
        exit 1
    }
    if ($mdmHealth.Enrolled) {
        $providerLabel = if ($mdmHealth.Provider -eq 'WMI_Bridge_SCCM_Server') { 'Co-management bridge' } else { 'Intune direct' }
        $upnDisplay = if ($mdmHealth.UPN) { " ($($mdmHealth.UPN))" } else { '' }
        $healthLines += "MDM:            Enrolled via $providerLabel$upnDisplay"
    }
    else {
        $healthLines += "MDM:            Not enrolled"
    }

    # Last WU scan freshness
    $scanStatus = Get-LastWUScanStatus
    if ($Config_MaxScanAgeDays -gt 0 -and $null -ne $scanStatus.AgeDays -and $scanStatus.AgeDays -gt $Config_MaxScanAgeDays) {
        $msg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason "Windows Update has not scanned in $($scanStatus.AgeDays) days (threshold: $Config_MaxScanAgeDays days)" `
            -Details @("  Last scan: $($scanStatus.LastScan)", "  Action: Investigate why the WU client is not scanning") `
            -UpdateSource $pdsStatus `
            -Health $healthLines `
            -Policy $indicators
        Write-Log "Stale WU scan: $($scanStatus.AgeDays) days"
        Write-Output $msg
        exit 1
    }
    if ($null -ne $scanStatus.AgeDays) {
        $healthLines += "Last WU scan:   $($scanStatus.AgeDays) days ago"
    }
    else {
        $healthLines += "Last WU scan:   Unknown"
    }

    # --- Compliant ---
    $reason = 'WUfB is managing all update types on this device'
    $wsusDetail = @()
    if ($hasWSUS) {
        $wsusDetail += "  Note: Stale WSUS config present ($wuServer) but fully overridden — WUfB is in control"
    }
    $msg = Format-Output -Result 'COMPLIANT' `
        -Reason $reason `
        -Details $wsusDetail `
        -UpdateSource $pdsStatus `
        -Health $healthLines `
        -Policy $indicators
    Write-Log "COMPLIANT"
    Write-Output $msg
    exit 0
}
catch {
    $msg = Format-Output -Result 'ERROR' -Reason "Detection failed — $($_.Exception.Message)"
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output $msg
    exit 1
}
