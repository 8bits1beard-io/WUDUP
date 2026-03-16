#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Detection Script - Checks if device is managed by Windows Update for Business.

.DESCRIPTION
    Intune Proactive Remediation detection script.
    Determines whether the device is receiving updates via WUfB (compliant)
    or another source such as WSUS, SCCM, or no policy at all (non-compliant).

    Checks for blockers that prevent WUfB from functioning:
    - NoAutoUpdate=1 or AUOptions=1 (automatic updates disabled)
    - DoNotConnectToWindowsUpdateInternetLocations=1 (WU connectivity blocked)
    - SetDisableUXWUAccess=1 (WU UI/access disabled)
    - Windows Update (wuauserv) or Update Orchestrator (UsoSvc) services disabled

    Checks all WUfB indicator registry locations:
    - SetPolicyDrivenUpdateSourceFor* keys (Feature/Quality/Driver/Other)
    - Deferral policies (GP and MDM paths)
    - Version targeting (TargetReleaseVersion / ProductVersion)
    - Compliance deadlines and grace periods
    - Channel targeting (BranchReadinessLevel)
    - Preview build management (ManagePreviewBuilds)
    - Driver exclusion (ExcludeWUDriversInQualityUpdate)

    Handles split-source scenarios where WSUS is configured but WUfB
    controls feature/quality updates via SetPolicyDrivenUpdateSource keys.

    Optionally verifies that an Intune WUfB Update Ring is actively delivering
    policy (not just that PolicyDrivenSource keys exist from remediation).
    Controlled by $Config_RequireUpdateRing.

    Validates management channel health:
    - Active MDM enrollment (Intune enrolled with valid state)
    - Recent Windows Update scan activity (configurable staleness threshold)

    Exit 0 = WUfB detected (compliant, no remediation needed)
    Exit 1 = WUfB not detected (non-compliant, triggers remediation)

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Detection v1.6.0
    Created: 12 March 2026
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

# Update Ring enforcement: set to $true to require an Intune WUfB Update Ring
# to be actively delivering policy. When $false (default), the device is
# compliant as long as WUfB indicators exist (including remediation-set
# PolicyDrivenSource keys). When $true, the device must also have WUfB policy
# values delivered by an active Intune enrollment — otherwise it reports
# non-compliant even if pointed at Windows Update.
$Config_RequireUpdateRing = $false

# MDM enrollment enforcement: set to $true to require an active Intune MDM
# enrollment. When $true, devices without a healthy MDM enrollment report
# non-compliant. Remediation cannot fix this — manual re-enrollment is needed.
$Config_RequireMDMEnrollment = $false

# Maximum days since last successful Windows Update scan before flagging
# non-compliant. Set to 0 to disable this check. When the WU client hasn't
# scanned within this window, the device may not be receiving updates even if
# configured correctly. Remediation cannot fix stale scans — manual
# investigation is needed.
$Config_MaxScanAgeDays = 0

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

# Reads a value from GP path first, then MDM path as fallback
function Get-PolicyValue {
    param([string]$Name)
    $val = Get-SafeRegistryValue -Path $RegPath_WU -Name $Name
    if ($null -ne $val) { return $val }
    return Get-SafeRegistryValue -Path $RegPath_MDM -Name $Name
}

# Checks whether an active Intune enrollment is delivering WUfB Update policy.
# Looks in PolicyManager\Providers\<EnrollmentGUID>\default\device\Update for
# WUfB-specific values (deferrals, deadlines, version targeting) that indicate
# an Update Ring assignment — not just PolicyDrivenSource keys from remediation.
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
        if ($providerID -ne 'MS DM Server') { continue }

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

# Checks for a healthy Intune MDM enrollment. Returns a hashtable with:
#   Enrolled = $true/$false   — whether an active Intune enrollment exists
#   UPN      = string|$null   — the enrolled user's UPN (if found)
#   GUID     = string|$null   — the enrollment GUID
function Test-MDMEnrollmentHealth {
    $result = @{ Enrolled = $false; UPN = $null; GUID = $null }
    $enrollPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path $enrollPath)) { return $result }

    $enrollments = Get-ChildItem -Path $enrollPath -ErrorAction SilentlyContinue
    foreach ($enrollment in $enrollments) {
        $providerID = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'ProviderID'
        if ($providerID -ne 'MS DM Server') { continue }

        $enrollState = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'EnrollmentState'
        # EnrollmentState 1 = enrolled and active
        if ($enrollState -ne 1) { continue }

        $result.Enrolled = $true
        $result.UPN = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'UPN'
        $result.GUID = $enrollment.PSChildName
        return $result
    }

    return $result
}

# Checks when the Windows Update client last completed a successful scan.
# Returns a hashtable with:
#   LastScan  = [DateTime]|$null  — timestamp of last successful detect
#   AgeDays   = [int]|$null       — days since last scan
function Get-LastWUScanStatus {
    $result = @{ LastScan = $null; AgeDays = $null }
    $detectPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
    $lastSuccess = Get-SafeRegistryValue -Path $detectPath -Name 'LastSuccessTime'
    if ($null -eq $lastSuccess) { return $result }

    try {
        $scanTime = [DateTime]::Parse($lastSuccess)
        $result.LastScan = $scanTime
        $result.AgeDays = [math]::Floor(((Get-Date) - $scanTime).TotalDays)
    }
    catch { }

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

    if ($featureFromWU) { $indicators += 'PolicyDrivenSource: Feature->WU' }
    if ($qualityFromWU) { $indicators += 'PolicyDrivenSource: Quality->WU' }
    if ($driverFromWU)  { $indicators += 'PolicyDrivenSource: Driver->WU' }
    if ($otherFromWU)   { $indicators += 'PolicyDrivenSource: Other->WU' }

    # --- 2. Deferral Policies ---
    $featureDefer = Get-PolicyValue -Name 'DeferFeatureUpdatesPeriodInDays'
    $qualityDefer = Get-PolicyValue -Name 'DeferQualityUpdatesPeriodInDays'

    if ($null -ne $featureDefer) { $indicators += "FeatureDeferral: ${featureDefer}d" }
    if ($null -ne $qualityDefer) { $indicators += "QualityDeferral: ${qualityDefer}d" }

    # --- 3. Version Targeting ---
    $targetEnabled = Get-PolicyValue -Name 'TargetReleaseVersion'
    $targetVersion = Get-PolicyValue -Name 'TargetReleaseVersionInfo'
    $productVersion = Get-PolicyValue -Name 'ProductVersion'

    if ($targetEnabled -eq 1 -and $null -ne $targetVersion) {
        $indicators += "VersionPin: $productVersion $targetVersion"
    }

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

    if ($null -ne $deadlineFeature) { $indicators += "FeatureDeadline: ${deadlineFeature}d" }
    if ($null -ne $deadlineQuality) { $indicators += "QualityDeadline: ${deadlineQuality}d" }
    if ($null -ne $deadlineGrace)   { $indicators += "GracePeriod: ${deadlineGrace}d" }
    if ($null -ne $deadlineGraceFU) { $indicators += "GracePeriodFU: ${deadlineGraceFU}d" }

    # --- 5. Channel / Preview Build Management ---
    $branchLevel = Get-PolicyValue -Name 'BranchReadinessLevel'
    $previewBuilds = Get-PolicyValue -Name 'ManagePreviewBuilds'

    if ($null -ne $branchLevel) { $indicators += "BranchReadiness: $branchLevel" }
    if ($null -ne $previewBuilds) { $indicators += "PreviewBuilds: $previewBuilds" }

    # --- 6. Driver Exclusion ---
    $excludeDrivers = Get-PolicyValue -Name 'ExcludeWUDriversInQualityUpdate'
    if ($null -ne $excludeDrivers) { $indicators += "ExcludeDrivers: $excludeDrivers" }

    # --- 7. Update Blocker Checks ---
    $blockers = @()

    # NoAutoUpdate=1 disables all automatic updates
    $noAutoUpdate = Get-SafeRegistryValue -Path $RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdate -eq 1) { $blockers += 'NoAutoUpdate=1' }

    # AUOptions=1 means "Never check for updates" — effectively disables WU
    $auOptions = Get-SafeRegistryValue -Path $RegPath_AU -Name 'AUOptions'
    if ($auOptions -eq 1) { $blockers += 'AUOptions=1 (Never check)' }

    # DoNotConnectToWindowsUpdateInternetLocations=1 blocks WU server connectivity
    $noConnect = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    if ($noConnect -eq 1) { $blockers += 'DoNotConnectToWindowsUpdateInternetLocations=1' }

    # SetDisableUXWUAccess=1 hides WU UI and can block update flows
    $disableUX = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetDisableUXWUAccess'
    if ($disableUX -eq 1) { $blockers += 'SetDisableUXWUAccess=1' }

    # Windows Update service (wuauserv) must not be disabled
    $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') { $blockers += 'wuauserv service Disabled' }

    # Update Orchestrator Service (UsoSvc) must not be disabled
    $usoSvc = Get-Service -Name 'UsoSvc' -ErrorAction SilentlyContinue
    if ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') { $blockers += 'UsoSvc service Disabled' }

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

    $hasWUfBIndicators = ($indicators.Count -gt 0)

    # Split-source: WSUS is configured but PolicyDrivenSource directs some update types to WU
    $anyPolicyDrivenToWU = ($featureFromWU -or $qualityFromWU -or $driverFromWU -or $otherFromWU)
    $isSplitSource = ($hasWSUS -and $anyPolicyDrivenToWU)

    # Blockers prevent WUfB from functioning — non-compliant regardless of other indicators
    if ($hasBlockers) {
        $blockerDetail = $blockers -join '; '
        $msg = "NON-COMPLIANT: Update blockers detected ($blockerDetail). WUfB policies cannot take effect."
        Write-Log $msg
        Write-Output $msg
        exit 1
    }

    if ($hasWUfBIndicators -and (-not $hasWSUS -or $isSplitSource)) {
        # WUfB is managing updates (either exclusively or via split-source)
        $detail = $indicators -join '; '

        # Check if an Intune Update Ring is actively delivering WUfB policy
        $hasUpdateRing = Test-IntuneUpdateRingDelivered

        if (-not $hasUpdateRing -and $Config_RequireUpdateRing) {
            $msg = "NON-COMPLIANT: Device is pointed at Windows Update but no Intune WUfB Update Ring policy detected. Assign an Update Ring to manage this device. $detail"
            Write-Log $msg
            Write-Output $msg
            exit 1
        }

        # --- Management channel health checks ---
        $healthWarnings = @()

        # MDM enrollment health
        $mdmHealth = Test-MDMEnrollmentHealth
        if ($Config_RequireMDMEnrollment -and -not $mdmHealth.Enrolled) {
            $msg = "NON-COMPLIANT: No active Intune MDM enrollment found. Device cannot receive WUfB policy from Intune. Manual re-enrollment required. $detail"
            Write-Log $msg
            Write-Output $msg
            exit 1
        }
        if ($mdmHealth.Enrolled) {
            $healthWarnings += "MDM: Enrolled ($($mdmHealth.UPN))"
        }
        else {
            $healthWarnings += 'MDM: Not enrolled'
        }

        # Last WU scan freshness
        $scanStatus = Get-LastWUScanStatus
        if ($Config_MaxScanAgeDays -gt 0 -and $null -ne $scanStatus.AgeDays -and $scanStatus.AgeDays -gt $Config_MaxScanAgeDays) {
            $msg = "NON-COMPLIANT: Windows Update has not scanned in $($scanStatus.AgeDays) days (threshold: ${Config_MaxScanAgeDays}d). Last scan: $($scanStatus.LastScan). Manual investigation required. $detail"
            Write-Log $msg
            Write-Output $msg
            exit 1
        }
        if ($null -ne $scanStatus.AgeDays) {
            $healthWarnings += "LastScan: $($scanStatus.AgeDays)d ago"
        }
        else {
            $healthWarnings += 'LastScan: Unknown'
        }

        $ringStatus = if ($hasUpdateRing) { ' [Update Ring: Active]' } else { ' [Update Ring: Not detected]' }
        $healthDetail = ' [' + ($healthWarnings -join ', ') + ']'

        if ($isSplitSource) {
            $msg = "COMPLIANT: WUfB detected (split-source with WSUS at $wuServer).$ringStatus$healthDetail $detail"
        }
        else {
            $msg = "COMPLIANT: WUfB detected.$ringStatus$healthDetail $detail"
        }
        Write-Log $msg
        Write-Output $msg
        exit 0
    }

    # Not WUfB — report why
    if ($hasWSUS -and $hasWUfBIndicators -and $disableDualScan -ne 1) {
        # WSUS active with WUfB indicators but no PolicyDrivenSource override and dual-scan not suppressed
        $msg = "NON-COMPLIANT: Dual-scan state (WSUS at $wuServer + WUfB policies). No PolicyDrivenSource override."
    }
    elseif ($hasWSUS -and $hasWUfBIndicators -and $disableDualScan -eq 1) {
        # WSUS active with WUfB indicators, but dual-scan is suppressed — still non-compliant but not dual-scan
        $msg = "NON-COMPLIANT: WSUS at $wuServer with WUfB policies present. DisableDualScan=1 suppresses dual-scan but no PolicyDrivenSource override."
    }
    elseif ($hasWSUS) {
        $wsusDetail = $wuServer
        if ($null -ne $wuStatusServer) { $wsusDetail += ", Status: $wuStatusServer" }
        $msg = "NON-COMPLIANT: Device is using WSUS ($wsusDetail), no WUfB policies detected."
    }
    elseif ($wuShiftedToIntune) {
        $msg = "NON-COMPLIANT: Co-managed device (WU workload assigned to Intune), no WUfB policies detected."
    }
    elseif ($hasSCCM) {
        $msg = "NON-COMPLIANT: Device is managed by SCCM/ConfigMgr. No WUfB policies detected."
    }
    else {
        $msg = "NON-COMPLIANT: No WUfB policies detected. Device using default Windows Update."
    }
    Write-Log $msg
    Write-Output $msg
    exit 1
}
catch {
    $msg = "ERROR: Detection failed - $($_.Exception.Message)"
    Write-Log $msg
    Write-Output $msg
    exit 1
}
