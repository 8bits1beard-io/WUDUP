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

$RegPath_WU        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$RegPath_MDM       = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
$RegPath_DO_Policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
$RegPath_DO_MDM    = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization'

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
        [string[]]$Checks,         # Per-check results ([PASS]/[FAIL]/[SKIP] lines)
        [string[]]$Issues,         # What failed (shown under "Issues Found:")
        [string[]]$Remediation,    # What to fix (shown under "Remediation:")
        [string[]]$Policy,         # WUfB policy lines
        [string[]]$Health          # Health check lines
    )
    $lines = @()
    $lines += "=== WUDUP Detection ==="
    $lines += "$Result — $Reason"

    if ($Checks -and $Checks.Count -gt 0) {
        $lines += ""
        $lines += "Checks Performed:"
        foreach ($c in $Checks) { $lines += $c }
    }

    if ($Issues -and $Issues.Count -gt 0) {
        $lines += ""
        $lines += "Issues Found:"
        foreach ($i in $Issues) { $lines += "  $i" }
    }

    if ($Remediation -and $Remediation.Count -gt 0) {
        $lines += ""
        $lines += "Remediation:"
        foreach ($r in $Remediation) { $lines += "  $r" }
    }

    if ($Health -and $Health.Count -gt 0) {
        $lines += ""
        $lines += "Management Channel:"
        foreach ($h in $Health) { $lines += "  $h" }
    }

    if ($Policy -and $Policy.Count -gt 0) {
        $lines += ""
        if ($Issues -and $Issues.Count -gt 0 -and $Result -eq 'NON-COMPLIANT') {
            $lines += "WUfB Policy (delivered but not effective — issues must be resolved first):"
        }
        else {
            $lines += "WUfB Policy (active):"
        }
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
    $result = @{ LastScan = $null; AgeDays = $null; LastInstall = $null }

    # Primary: COM Microsoft.Update.AutoUpdate — actual scan timestamp (not install history)
    try {
        $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
        $searchDate = $autoUpdate.Results.LastSearchSuccessDate
        if ($null -ne $searchDate -and $searchDate -gt [DateTime]::MinValue) {
            $result.LastScan = $searchDate
            $result.AgeDays = [math]::Floor(((Get-Date) - $searchDate).TotalDays)
        }
        $installDate = $autoUpdate.Results.LastInstallationSuccessDate
        if ($null -ne $installDate -and $installDate -gt [DateTime]::MinValue) {
            $result.LastInstall = $installDate
        }
    }
    catch { }

    # Secondary fallback: COM update history (checks install events, not scan events)
    if ($null -eq $result.LastScan) {
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $total = $searcher.GetTotalHistoryCount()
            if ($total -gt 0) {
                $latest = $searcher.QueryHistory(0, 1)
                if ($null -ne $latest -and $latest.Count -gt 0 -and $latest.Item(0).Date -gt [DateTime]::MinValue) {
                    $result.LastScan = $latest.Item(0).Date
                    $result.AgeDays = [math]::Floor(((Get-Date) - $result.LastScan).TotalDays)
                }
            }
        }
        catch { }
    }

    # Tertiary fallback: legacy Auto Update registry path (may be stale on modern Windows)
    if ($null -eq $result.LastScan) {
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
    }

    return $result
}

# ============================================================================
#  DETECTION LOGIC
# ============================================================================

try {
    Write-Log "Detection started"
    $indicators = @()
    $checks = @()

    # --- 1. Update Blocker Checks ---
    # NoAutoUpdate=1 disables all automatic updates
    $noAutoUpdate = Get-SafeRegistryValue -Path $RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdate -eq 1) {
        $checks += "  [FAIL] NoAutoUpdate = 1 — automatic updates disabled"
        $checks += "           $RegPath_AU\NoAutoUpdate"
    }
    else {
        $checks += "  [PASS] NoAutoUpdate != 1                         ($RegPath_AU)"
    }

    # AUOptions=1 means "Never check for updates" — effectively disables WU
    $auOptions = Get-SafeRegistryValue -Path $RegPath_AU -Name 'AUOptions'
    if ($auOptions -eq 1) {
        $checks += "  [FAIL] AUOptions = 1 — set to never check for updates"
        $checks += "           $RegPath_AU\AUOptions"
    }
    else {
        $checks += "  [PASS] AUOptions != 1                            ($RegPath_AU)"
    }

    # DoNotConnectToWindowsUpdateInternetLocations=1 blocks WU server connectivity
    $noConnect = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    if ($noConnect -eq 1) {
        $checks += "  [FAIL] DoNotConnectToWindowsUpdateInternetLocations = 1 — WU connectivity blocked"
        $checks += "           $RegPath_WU\DoNotConnectToWindowsUpdateInternetLocations"
    }
    else {
        $checks += "  [PASS] DoNotConnectToWindowsUpdateInternetLocations != 1  ($RegPath_WU)"
    }

    # SetDisableUXWUAccess=1 hides WU UI and can block update flows
    $disableUX = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetDisableUXWUAccess'
    if ($disableUX -eq 1) {
        $checks += "  [FAIL] SetDisableUXWUAccess = 1 — Windows Update UI/access disabled"
        $checks += "           $RegPath_WU\SetDisableUXWUAccess"
    }
    else {
        $checks += "  [PASS] SetDisableUXWUAccess != 1                 ($RegPath_WU)"
    }

    # DisableWindowsUpdateAccess=1 turns off access to all Windows Update features
    # Separate from SetDisableUXWUAccess — Microsoft Autopatch checks for this specifically
    $disableWUAccess = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DisableWindowsUpdateAccess'
    if ($disableWUAccess -eq 1) {
        $checks += "  [FAIL] DisableWindowsUpdateAccess = 1 — all Windows Update features disabled"
        $checks += "           $RegPath_WU\DisableWindowsUpdateAccess"
    }
    else {
        $checks += "  [PASS] DisableWindowsUpdateAccess != 1            ($RegPath_WU)"
    }

    # MDM AllowAutoUpdate=5 disables automatic updates via Intune/MDM policy
    $mdmAllowAutoUpdate = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'AllowAutoUpdate'
    if ($mdmAllowAutoUpdate -eq 5) {
        $checks += "  [FAIL] MDM AllowAutoUpdate = 5 — automatic updates disabled via MDM policy"
        $checks += "           $RegPath_MDM\AllowAutoUpdate"
    }
    else {
        $checks += "  [PASS] MDM AllowAutoUpdate != 5                   ($RegPath_MDM)"
    }

    # MDM AllowUpdateService=0 blocks device from using WU/WSUS/Store entirely
    $mdmAllowUpdateService = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'AllowUpdateService'
    if ($mdmAllowUpdateService -eq 0) {
        $checks += "  [FAIL] MDM AllowUpdateService = 0 — all update services blocked via MDM policy"
        $checks += "           $RegPath_MDM\AllowUpdateService"
    }
    else {
        $checks += "  [PASS] MDM AllowUpdateService != 0                ($RegPath_MDM)"
    }

    # Windows Update service (wuauserv) must not be disabled
    $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] wuauserv service Disabled — Windows Update cannot run"
    }
    else {
        $checks += "  [PASS] wuauserv service enabled"
    }

    # Update Orchestrator Service (UsoSvc) must not be disabled
    $usoSvc = Get-Service -Name 'UsoSvc' -ErrorAction SilentlyContinue
    if ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] UsoSvc service Disabled — Update Orchestrator cannot run"
    }
    else {
        $checks += "  [PASS] UsoSvc service enabled"
    }

    # Note: $orphanedUseWUServer is evaluated after WSUS section and added to $hasBlockers there
    $hasBlockers = (
        $noAutoUpdate -eq 1 -or
        $auOptions -eq 1 -or
        $noConnect -eq 1 -or
        $disableUX -eq 1 -or
        $disableWUAccess -eq 1 -or
        $mdmAllowAutoUpdate -eq 5 -or
        $mdmAllowUpdateService -eq 0 -or
        ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') -or
        ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled')
    )

    # --- 2. SCCM Detection ---
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

    if ($hasSCCM) {
        $checks += "  [FAIL] SCCM controlling updates — WU workload not shifted to Intune"
        $checks += "           HKLM:\SOFTWARE\Microsoft\CCM\CoManagementFlags"
    }
    else {
        $checks += "  [PASS] SCCM not controlling updates"
    }

    # --- 3. Policy-Driven Update Source (most definitive, Windows 10 2004+) ---
    # Read GP and MDM separately — MDM-delivered PolicyDrivenSource=0 overrides GP on the WU client
    $srcFeature_GP  = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcFeature_MDM = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_GP  = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcQuality_MDM = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcDriver_GP   = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcDriver_MDM  = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcOther_GP    = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'
    $srcOther_MDM   = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'

    # Value 0 = Windows Update (WUfB), Value 1 = WSUS — either path having 0 means WUfB wins
    $featureFromWU = ($srcFeature_GP -eq 0 -or $srcFeature_MDM -eq 0)
    $qualityFromWU = ($srcQuality_GP -eq 0 -or $srcQuality_MDM -eq 0)
    $driverFromWU  = ($srcDriver_GP -eq 0 -or $srcDriver_MDM -eq 0)
    $otherFromWU   = ($srcOther_GP -eq 0 -or $srcOther_MDM -eq 0)

    # Build per-type check lines with registry path detail on FAIL
    foreach ($type in @('Feature','Quality','Driver','Other')) {
        $gpVal  = Get-Variable -Name "src${type}_GP" -ValueOnly
        $mdmVal = Get-Variable -Name "src${type}_MDM" -ValueOnly
        $fromWU = Get-Variable -Name "$($type.ToLower())FromWU" -ValueOnly

        if ($fromWU) {
            $source = if ($mdmVal -eq 0) { $RegPath_MDM } else { $RegPath_WU }
            $checks += "  [PASS] PolicyDrivenSource $type = 0 (WUfB)    ($source)"
        }
        elseif ($null -eq $gpVal -and $null -eq $mdmVal) {
            $checks += "  [FAIL] PolicyDrivenSource $type = NOT SET"
            $checks += "           GP:  $RegPath_WU"
            $checks += "           MDM: $RegPath_MDM"
        }
        else {
            $checks += "  [FAIL] PolicyDrivenSource $type = WSUS (value 1), needs WUfB (value 0)"
            $checks += "           GP:  $RegPath_WU"
            $checks += "           MDM: $RegPath_MDM"
        }
    }

    # --- 4. WSUS Configuration ---
    $wuServer       = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUServer'
    $wuStatusServer = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUStatusServer'
    $useWUServer    = Get-SafeRegistryValue -Path $RegPath_AU -Name 'UseWUServer'
    $hasWSUS        = ($useWUServer -eq 1 -and $null -ne $wuServer)

    # Orphaned UseWUServer=1 without a valid WUServer — WU client points at nothing
    $orphanedUseWUServer = ($useWUServer -eq 1 -and ($null -eq $wuServer -or $wuServer -eq ''))
    if ($orphanedUseWUServer) {
        $checks += "  [FAIL] UseWUServer=1 but WUServer is empty — updates cannot reach any server"
        $checks += "           $RegPath_AU\UseWUServer"
        $hasBlockers = $true
    }

    # --- 5. Dual-Scan Suppression ---
    $disableDualScan = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DisableDualScan'

    # ========================================================================
    #  COLLECT HEALTH DATA (before compliance gates, so all exits have context)
    # ========================================================================

    $hasUpdateRing = Test-IntuneUpdateRingDelivered
    $mdmHealth     = Test-MDMEnrollmentHealth
    $scanStatus    = Get-LastWUScanStatus

    # --- 6. Update Ring delivery ---
    if (-not $Config_RequireUpdateRing) {
        $checks += "  [SKIP] Update Ring check disabled (`$Config_RequireUpdateRing = `$false)"
    }
    elseif ($hasUpdateRing) {
        $checks += "  [PASS] Intune Update Ring delivering policy"
    }
    else {
        $checks += "  [FAIL] No Intune Update Ring delivering policy"
        $checks += "           HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\<GUID>\default\device\Update"
    }

    # --- 7. MDM enrollment ---
    if (-not $Config_RequireMDMEnrollment) {
        $checks += "  [SKIP] MDM enrollment check disabled (`$Config_RequireMDMEnrollment = `$false)"
    }
    elseif ($mdmHealth.Enrolled) {
        $providerLabel = if ($mdmHealth.Provider -eq 'WMI_Bridge_SCCM_Server') { 'Co-management bridge' } else { 'Intune direct' }
        $upnDisplay = if ($mdmHealth.UPN) { ", $($mdmHealth.UPN)" } else { '' }
        $checks += "  [PASS] MDM enrollment active                     ($providerLabel$upnDisplay)"
    }
    else {
        $checks += "  [FAIL] No active MDM enrollment — device cannot receive WUfB policy"
        $checks += "           HKLM:\SOFTWARE\Microsoft\Enrollments"
    }

    # --- 8. WU scan freshness ---
    if ($Config_MaxScanAgeDays -le 0) {
        $checks += "  [SKIP] WU scan freshness check disabled (`$Config_MaxScanAgeDays = 0)"
    }
    elseif ($null -eq $scanStatus.AgeDays) {
        $checks += "  [PASS] WU scan age unknown (no history available)"
    }
    elseif ($scanStatus.AgeDays -gt $Config_MaxScanAgeDays) {
        $checks += "  [FAIL] WU scan stale — $($scanStatus.AgeDays) days ago (threshold: $Config_MaxScanAgeDays)"
    }
    else {
        $checks += "  [PASS] WU scan current                           ($($scanStatus.AgeDays) days ago, threshold: $Config_MaxScanAgeDays)"
    }

    # ========================================================================
    #  COLLECT HEALTH SUMMARY
    # ========================================================================

    $healthLines = @()
    $healthLines += "Update Ring:    $(if ($hasUpdateRing) { 'Active' } else { 'Not detected' })"
    if ($mdmHealth.Enrolled) {
        $providerLabel = if ($mdmHealth.Provider -eq 'WMI_Bridge_SCCM_Server') { 'Co-management bridge' } else { 'Intune direct' }
        $upnDisplay = if ($mdmHealth.UPN) { " ($($mdmHealth.UPN))" } else { '' }
        $healthLines += "MDM:            Enrolled via $providerLabel$upnDisplay"
    }
    else {
        $healthLines += "MDM:            Not enrolled"
    }
    if ($null -ne $scanStatus.AgeDays) {
        $healthLines += "Last WU scan:   $($scanStatus.AgeDays) days ago"
    }
    else {
        $healthLines += "Last WU scan:   Unknown"
    }
    if ($null -ne $scanStatus.LastInstall) {
        $healthLines += "Last install:   $($scanStatus.LastInstall.ToString('yyyy-MM-dd HH:mm'))"
    }

    # Pending reboot detection — informational, not a compliance gate
    $pendingReboot = $false
    try {
        $sysInfo = New-Object -ComObject Microsoft.Update.SystemInfo
        $pendingReboot = [bool]$sysInfo.RebootRequired
    }
    catch { }
    if (-not $pendingReboot) {
        $pendingReboot = (
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
            (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
        )
    }
    $healthLines += "Pending reboot: $(if ($pendingReboot) { 'Yes' } else { 'No' })"

    # Delivery Optimization mode — warn if mode 100 (Bypass, deprecated on Win11)
    $doGP  = Get-SafeRegistryValue -Path $RegPath_DO_Policy -Name 'DownloadMode'
    $doMDM = Get-SafeRegistryValue -Path $RegPath_DO_MDM -Name 'DODownloadMode'
    $doMode = if ($null -ne $doGP) { $doGP } elseif ($null -ne $doMDM) { $doMDM } else { $null }
    if ($doMode -eq 100) {
        $healthLines += "DO Mode:        100 (Bypass) — DEPRECATED on Win11, may cause download failures"
    }

    # Supporting services — warn only if Disabled (not compliance gates)
    $cryptSvc = Get-Service -Name 'cryptsvc' -ErrorAction SilentlyContinue
    if ($null -ne $cryptSvc -and $cryptSvc.StartType -eq 'Disabled') {
        $healthLines += "cryptsvc:       Disabled — certificate/signature verification may fail"
    }
    $tiSvc = Get-Service -Name 'TrustedInstaller' -ErrorAction SilentlyContinue
    if ($null -ne $tiSvc -and $tiSvc.StartType -eq 'Disabled') {
        $healthLines += "TrustedInstaller: Disabled — pending servicing transactions may be blocked"
    }

    # ========================================================================
    #  COLLECT WUfB POLICY INDICATORS (informational, not compliance gates)
    # ========================================================================

    # --- Deferral Policies ---
    $featureDefer = Get-PolicyValue -Name 'DeferFeatureUpdatesPeriodInDays'
    $qualityDefer = Get-PolicyValue -Name 'DeferQualityUpdatesPeriodInDays'

    # Check deferral enable flags — GP has separate enable flags alongside the period values
    $featureDeferEnabled = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DeferFeatureUpdates'
    $qualityDeferEnabled = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DeferQualityUpdates'

    if ($null -ne $featureDefer -and $featureDefer -gt 0) {
        if ($featureDeferEnabled -eq 0) {
            $indicators += "Feature deferral:       $featureDefer days (WARNING: DeferFeatureUpdates enable flag = 0)"
        }
        else {
            $indicators += "Feature deferral:       $featureDefer days"
        }
    }
    if ($null -ne $qualityDefer -and $qualityDefer -gt 0) {
        if ($qualityDeferEnabled -eq 0) {
            $indicators += "Quality deferral:       $qualityDefer days (WARNING: DeferQualityUpdates enable flag = 0)"
        }
        else {
            $indicators += "Quality deferral:       $qualityDefer days"
        }
    }

    # --- Version Targeting ---
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

    # --- Compliance Deadlines ---
    # GP writes native names (ComplianceDeadlineForFU, ComplianceDeadline); MDM uses Configure* names
    # Read GP first (both naming conventions), then MDM fallback — matches WUDUP.ps1 pattern
    $deadlineFeature = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ConfigureDeadlineForFeatureUpdates'
    if ($null -eq $deadlineFeature) { $deadlineFeature = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceDeadlineForFU' }
    if ($null -eq $deadlineFeature) { $deadlineFeature = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineForFeatureUpdates' }

    $deadlineQuality = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ConfigureDeadlineForQualityUpdates'
    if ($null -eq $deadlineQuality) { $deadlineQuality = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceDeadline' }
    if ($null -eq $deadlineQuality) { $deadlineQuality = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineForQualityUpdates' }

    $deadlineGrace = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ConfigureDeadlineGracePeriod'
    if ($null -eq $deadlineGrace) { $deadlineGrace = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceGracePeriod' }
    if ($null -eq $deadlineGrace) { $deadlineGrace = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineGracePeriod' }

    $deadlineGraceFU = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates'
    if ($null -eq $deadlineGraceFU) { $deadlineGraceFU = Get-SafeRegistryValue -Path $RegPath_WU -Name 'ComplianceGracePeriodForFU' }
    if ($null -eq $deadlineGraceFU) { $deadlineGraceFU = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates' }

    if ($null -ne $deadlineFeature) { $indicators += "Feature deadline:       $deadlineFeature days" }
    if ($null -ne $deadlineQuality) { $indicators += "Quality deadline:       $deadlineQuality days" }
    if ($null -ne $deadlineGrace)   { $indicators += "Grace period:           $deadlineGrace days" }
    if ($null -ne $deadlineGraceFU) { $indicators += "Grace period (feature): $deadlineGraceFU days" }

    # --- Channel / Preview Build Management ---
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

    # --- Driver Exclusion ---
    $excludeDrivers = Get-PolicyValue -Name 'ExcludeWUDriversInQualityUpdate'
    if ($null -ne $excludeDrivers) {
        $driverName = if ($excludeDrivers -eq 1) { 'Excluded from quality updates' } else { 'Included in quality updates' }
        $indicators += "Driver updates:         $driverName"
    }

    # ========================================================================
    #  EVALUATE COMPLIANCE — collect ALL issues before outputting
    # ========================================================================

    $allPolicyDrivenToWU = ($featureFromWU -and $qualityFromWU -and $driverFromWU -and $otherFromWU)
    $issues = @()       # What's wrong
    $remediation = @()  # What to fix

    # --- Check 1: Update blockers ---
    if ($hasBlockers) {
        $hasMDMBlockers = $false
        if ($noAutoUpdate -eq 1)   { $issues += 'NoAutoUpdate=1 in AU subkey — automatic updates are disabled' }
        if ($auOptions -eq 1)      { $issues += 'AUOptions=1 in AU subkey — set to never check for updates' }
        if ($noConnect -eq 1)      { $issues += 'DoNotConnectToWindowsUpdateInternetLocations=1 — WU server connectivity blocked' }
        if ($disableUX -eq 1)      { $issues += 'SetDisableUXWUAccess=1 — Windows Update UI/access disabled' }
        if ($disableWUAccess -eq 1) { $issues += 'DisableWindowsUpdateAccess=1 — all Windows Update features disabled' }
        if ($mdmAllowAutoUpdate -eq 5) {
            $issues += 'MDM AllowAutoUpdate=5 — automatic updates disabled via Intune/MDM policy'
            $hasMDMBlockers = $true
        }
        if ($mdmAllowUpdateService -eq 0) {
            $issues += 'MDM AllowUpdateService=0 — all update services blocked via Intune/MDM policy'
            $hasMDMBlockers = $true
        }
        if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled')  { $issues += 'wuauserv service startup set to Disabled — Windows Update cannot run' }
        if ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') { $issues += 'UsoSvc service startup set to Disabled — Update Orchestrator cannot run' }
        if ($orphanedUseWUServer) { $issues += 'UseWUServer=1 but WUServer is empty/null — WU client cannot reach any update server' }
        $remediation += "Remove update blockers (remediation script handles this automatically)"
        if ($hasMDMBlockers) {
            $remediation += "Review Intune device configuration profiles — MDM-delivered blockers cannot be fixed by remediation script"
        }
    }

    # --- Check 2: SCCM controlling updates ---
    if ($hasSCCM) {
        $issues += "SCCM/ConfigMgr is managing updates (WU workload not shifted to Intune)"
        $remediation += "Shift the Windows Update workload to Intune in co-management settings"
    }

    # --- Check 3: PolicyDrivenSource keys ---
    if (-not $allPolicyDrivenToWU) {
        foreach ($type in @('Feature','Quality','Driver','Other')) {
            $gp  = Get-Variable -Name "src${type}_GP" -ValueOnly
            $mdm = Get-Variable -Name "src${type}_MDM" -ValueOnly
            if ($null -eq $gp -and $null -eq $mdm) {
                $issues += "$type updates: PolicyDrivenSource not configured (missing)"
            }
            elseif ($gp -ne 0 -and $mdm -ne 0) {
                $issues += "$type updates: PolicyDrivenSource set to WSUS (value 1), needs WUfB (value 0)"
            }
        }
        if ($hasWSUS) {
            $issues += "WSUS server configured: $wuServer — will control misconfigured update types"
        }
        $remediation += "Set all 4 PolicyDrivenSource keys to 0 (remediation script handles this automatically)"
    }

    # --- Check 4: Update Ring delivery ---
    if ($Config_RequireUpdateRing -and -not $hasUpdateRing) {
        $issues += "No Intune WUfB Update Ring is actively delivering policy to this device"
        $remediation += "Assign a WUfB Update Ring to this device in Intune"
    }

    # --- Check 5: MDM enrollment ---
    if ($Config_RequireMDMEnrollment -and -not $mdmHealth.Enrolled) {
        $issues += "No active Intune MDM enrollment — device cannot receive WUfB policy"
        $remediation += "Re-enroll this device in Intune (manual action required)"
    }

    # --- Check 6: WU scan freshness ---
    if ($Config_MaxScanAgeDays -gt 0 -and $null -ne $scanStatus.AgeDays -and $scanStatus.AgeDays -gt $Config_MaxScanAgeDays) {
        $issues += "Windows Update has not scanned in $($scanStatus.AgeDays) days (threshold: $Config_MaxScanAgeDays)"
        $remediation += "Investigate why the WU client is not scanning (manual action required)"
    }

    # --- Output result ---
    if ($issues.Count -gt 0) {
        $reason = "$($issues.Count) issue$(if ($issues.Count -gt 1) { 's' }) found — device is not WUfB compliant"
        $msg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason $reason `
            -Checks $checks `
            -Issues $issues `
            -Remediation $remediation `
            -Health $healthLines `
            -Policy $indicators
        Write-Log "NON-COMPLIANT: $($issues -join '; ')"
        Write-Output $msg
        exit 1
    }

    # --- Compliant ---
    $notes = @()
    if ($hasWSUS) {
        $notes += "Stale WSUS config present ($wuServer) but fully overridden — WUfB is in control"
    }
    $msg = Format-Output -Result 'COMPLIANT' `
        -Reason 'WUfB is managing all update types on this device' `
        -Checks $checks `
        -Issues $notes `
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
