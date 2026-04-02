#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Detection Script - Checks if device is fully managed by Windows Update for Business.

.DESCRIPTION
    Intune Proactive Remediation detection script.
    Determines whether the device's update infrastructure is correctly
    configured for WUfB (via Intune) to manage ALL updates — or whether
    any setting is blocking, overriding, or conflicting with that goal.

    Assumption: every device should be enrolled in Intune and receiving a
    WUfB Update Ring. Devices should NOT be managed by AD GPO, LGPO, or SCCM.

    Primary compliance gates (evaluated in order):
    1.  No update blockers (registry + services)
    2.  No SCCM controlling updates (unless co-mgmt WU workload shifted)
    3.  All four PolicyDrivenSource keys = 0 (WU) for Feature/Quality/Driver/Other
    4.  No stale pauses (policy-level or UX-level)
    5.  No legacy dual-scan artifacts (DeferUpgrade)
    6.  No GP/LGPO policy conflicts that Intune cannot override

    Secondary gates (configurable):
    7.  Intune Update Ring actively delivering policy
    8.  Active MDM enrollment
    9.  Recent Windows Update scan activity

    Exit 0 = WUfB compliant (no blockers, no conflicts, receiving policy)
    Exit 1 = Non-compliant (triggers remediation)

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Detection v2.0.0
    Created: 12 March 2026
    Updated: 1 April 2026
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

# Require an Intune WUfB Update Ring to be actively delivering policy.
# Set $false if you only need to verify the device is pointed at WU (no ring check).
$Config_RequireUpdateRing = $true

# Require an active Intune MDM enrollment (EnrollmentState=1).
# Remediation cannot fix this — manual re-enrollment is needed.
$Config_RequireMDMEnrollment = $true

# Maximum days since last successful WU scan before flagging non-compliant.
# Set 0 to disable. Remediation cannot fix stale scans.
$Config_MaxScanAgeDays = 7

# Treat leftover WSUS registry keys as FAIL even when PolicyDrivenSource=0
# overrides them. When $false, they are reported as WARN (informational).
$Config_TreatWSUSArtifactsAsFail = $false

# Scan for GP/LGPO policy values under the WU and AU registry paths that
# Intune cannot override (MDMWinsOverGP does NOT apply to Update CSP).
# Any unexpected value found is flagged as a conflict.
$Config_CheckGPConflicts = $true

# ============================================================================
#  REGISTRY PATHS
# ============================================================================

$RegPath_WU      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU      = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$RegPath_MDM     = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
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

# Builds structured multi-line output for the Intune portal (admin-readable).
# Intune uses the exit code for compliance; this text is for troubleshooting.
function Format-Output {
    param(
        [string]$Result,           # COMPLIANT / NON-COMPLIANT / ERROR
        [string]$Reason,           # One-line summary
        [string[]]$Checks,         # Per-check [PASS]/[FAIL]/[SKIP]/[WARN] lines
        [string[]]$Issues,         # What failed
        [string[]]$Remediation,    # How to fix it
        [string[]]$Policy,         # WUfB policy indicators (informational)
        [string[]]$Health          # Management channel health
    )
    $lines = @()
    $lines += "=== WUDUP Detection ==="
    $lines += "$Result -- $Reason"

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
            $lines += "WUfB Policy (delivered but not effective -- issues must be resolved first):"
        }
        else {
            $lines += "WUfB Policy (active):"
        }
        foreach ($p in $Policy) { $lines += "  $p" }
    }

    return ($lines -join "`n")
}

# Reads a value from GP path first, then MDM path as fallback.
function Get-PolicyValue {
    param([string]$Name)
    $val = Get-SafeRegistryValue -Path $RegPath_WU -Name $Name
    if ($null -ne $val) { return $val }
    return Get-SafeRegistryValue -Path $RegPath_MDM -Name $Name
}

# MDM provider IDs that deliver WUfB policy.
# 'MS DM Server'         = direct Intune enrollment
# 'WMI_Bridge_SCCM_Server' = SCCM co-management bridge
$MDMProviderIDs = @('MS DM Server', 'WMI_Bridge_SCCM_Server')

# Checks whether an active MDM enrollment is delivering WUfB Update Ring policy.
# Looks for WUfB-specific values in PolicyManager\Providers\<GUID>\default\device\Update.
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

# Checks for a healthy MDM enrollment.
# Returns: Enrolled, UPN, GUID, Provider
function Test-MDMEnrollmentHealth {
    $result = @{ Enrolled = $false; UPN = $null; GUID = $null; Provider = $null }
    $enrollPath = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
    if (-not (Test-Path $enrollPath)) { return $result }

    $enrollments = Get-ChildItem -Path $enrollPath -ErrorAction SilentlyContinue
    foreach ($enrollment in $enrollments) {
        $providerID = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'ProviderID'
        if ($providerID -notin $MDMProviderIDs) { continue }

        $enrollState = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'EnrollmentState'
        if ($enrollState -ne 1) { continue }

        $result.Enrolled  = $true
        $result.UPN       = Get-SafeRegistryValue -Path $enrollment.PSPath -Name 'UPN'
        $result.GUID      = $enrollment.PSChildName
        $result.Provider  = $providerID
        return $result
    }

    return $result
}

# Returns when the WU client last had activity (COM primary, registry fallback).
# Returns: LastScan ([DateTime]|$null), AgeDays ([int]|$null)
function Get-LastWUScanStatus {
    $result = @{ LastScan = $null; AgeDays = $null }

    try {
        $session  = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total    = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $latest = $searcher.QueryHistory(0, 1)
            if ($null -ne $latest -and $latest.Count -gt 0 -and $latest.Item(0).Date -gt [DateTime]::MinValue) {
                $result.LastScan = $latest.Item(0).Date
                $result.AgeDays  = [math]::Floor(((Get-Date) - $result.LastScan).TotalDays)
                return $result
            }
        }
    }
    catch { }

    $detectPath  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect'
    $lastSuccess = Get-SafeRegistryValue -Path $detectPath -Name 'LastSuccessTime'
    if ($null -ne $lastSuccess) {
        try {
            $scanTime        = [DateTime]::Parse($lastSuccess)
            $result.LastScan = $scanTime
            $result.AgeDays  = [math]::Floor(((Get-Date) - $scanTime).TotalDays)
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
    $checks     = @()
    $issues     = @()
    $remediation = @()

    # ========================================================================
    #  SECTION 1: UPDATE BLOCKERS
    # ========================================================================
    $checks += "--- Update Blockers ---"

    # NoAutoUpdate=1 disables all automatic updates
    $noAutoUpdate = Get-SafeRegistryValue -Path $RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdate -eq 1) {
        $checks += "  [FAIL] NoAutoUpdate = 1 -- automatic updates disabled"
        $checks += "           $RegPath_AU\NoAutoUpdate"
    }
    else {
        $checks += "  [PASS] NoAutoUpdate != 1                         ($RegPath_AU)"
    }

    # AUOptions=1 = "Never check for updates"
    $auOptions = Get-SafeRegistryValue -Path $RegPath_AU -Name 'AUOptions'
    if ($auOptions -eq 1) {
        $checks += "  [FAIL] AUOptions = 1 -- set to never check for updates"
        $checks += "           $RegPath_AU\AUOptions"
    }
    else {
        $checks += "  [PASS] AUOptions != 1                            ($RegPath_AU)"
    }

    # DoNotConnectToWindowsUpdateInternetLocations=1 blocks WU server connectivity
    $noConnect = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    if ($noConnect -eq 1) {
        $checks += "  [FAIL] DoNotConnectToWindowsUpdateInternetLocations = 1 -- WU connectivity blocked"
        $checks += "           $RegPath_WU\DoNotConnectToWindowsUpdateInternetLocations"
    }
    else {
        $checks += "  [PASS] DoNotConnectToWindowsUpdateInternetLocations != 1  ($RegPath_WU)"
    }

    # SetDisableUXWUAccess=1 hides WU UI and can block update flows
    $disableUX = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetDisableUXWUAccess'
    if ($disableUX -eq 1) {
        $checks += "  [FAIL] SetDisableUXWUAccess = 1 -- Windows Update UI/access disabled"
        $checks += "           $RegPath_WU\SetDisableUXWUAccess"
    }
    else {
        $checks += "  [PASS] SetDisableUXWUAccess != 1                 ($RegPath_WU)"
    }

    # DisableWindowsUpdateAccess blocks all WU access (Autopatch top-3 blocker)
    $disableWUAccess = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DisableWindowsUpdateAccess'
    if ($null -ne $disableWUAccess) {
        $checks += "  [FAIL] DisableWindowsUpdateAccess = $disableWUAccess -- all Windows Update access blocked"
        $checks += "           $RegPath_WU\DisableWindowsUpdateAccess"
    }
    else {
        $checks += "  [PASS] DisableWindowsUpdateAccess not set        ($RegPath_WU)"
    }

    # DisableOSUpgrade=1 blocks feature update upgrades (e.g. Win10 -> Win11)
    $disableOSUpgrade = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DisableOSUpgrade'
    if ($disableOSUpgrade -eq 1) {
        $checks += "  [FAIL] DisableOSUpgrade = 1 -- OS feature update upgrades blocked"
        $checks += "           $RegPath_WU\DisableOSUpgrade"
    }
    else {
        $checks += "  [PASS] DisableOSUpgrade != 1                     ($RegPath_WU)"
    }

    # NoWindowsUpdate (Explorer policy path) removes access to Windows Update
    $noWUExplorer = Get-SafeRegistryValue -Path $RegPath_Explorer -Name 'NoWindowsUpdate'
    if ($noWUExplorer -eq 1) {
        $checks += "  [FAIL] NoWindowsUpdate = 1 -- Windows Update access removed (Explorer policy)"
        $checks += "           $RegPath_Explorer\NoWindowsUpdate"
    }
    else {
        $checks += "  [PASS] NoWindowsUpdate not set (Explorer policy) ($RegPath_Explorer)"
    }

    # DisableWindowsUpdateAccess at alternate legacy policy path
    $disableWUAltPath = Get-SafeRegistryValue -Path $RegPath_WUPol -Name 'DisableWindowsUpdateAccess'
    if ($null -ne $disableWUAltPath) {
        $checks += "  [FAIL] DisableWindowsUpdateAccess = $disableWUAltPath -- WU access blocked (legacy policy path)"
        $checks += "           $RegPath_WUPol\DisableWindowsUpdateAccess"
    }
    else {
        $checks += "  [PASS] DisableWindowsUpdateAccess not set (legacy policy path)"
    }

    # AllowAutoUpdate=0 via MDM/CSP disables automatic updates at the CSP layer
    # Note: Intune delivers this via PolicyManager; a value of 0 disables updates
    $allowAutoUpdate = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'AllowAutoUpdate'
    if ($null -ne $allowAutoUpdate -and $allowAutoUpdate -eq 0) {
        $checks += "  [FAIL] AllowAutoUpdate = 0 -- automatic updates disabled via MDM/CSP"
        $checks += "           $RegPath_MDM\AllowAutoUpdate"
    }
    else {
        $checks += "  [PASS] AllowAutoUpdate != 0                      ($RegPath_MDM)"
    }

    # wuauserv must not be Disabled
    $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] wuauserv service Disabled -- Windows Update cannot run"
    }
    else {
        $checks += "  [PASS] wuauserv service enabled"
    }

    # UsoSvc must not be Disabled
    $usoSvc = Get-Service -Name 'UsoSvc' -ErrorAction SilentlyContinue
    if ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] UsoSvc service Disabled -- Update Orchestrator cannot run"
    }
    else {
        $checks += "  [PASS] UsoSvc service enabled"
    }

    # WaaSMedicSvc -- self-healing for WU; if Disabled, wuauserv/UsoSvc won't auto-recover
    $medicSvc = Get-Service -Name 'WaaSMedicSvc' -ErrorAction SilentlyContinue
    if ($null -ne $medicSvc -and $medicSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] WaaSMedicSvc service Disabled -- WU self-healing broken"
    }
    else {
        $checks += "  [PASS] WaaSMedicSvc service enabled"
    }

    # BITS -- Background Intelligent Transfer Service; needed to download updates
    $bitsSvc = Get-Service -Name 'bits' -ErrorAction SilentlyContinue
    if ($null -ne $bitsSvc -and $bitsSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] bits service Disabled -- update downloads will fail"
    }
    else {
        $checks += "  [PASS] bits service enabled"
    }

    # cryptsvc -- Cryptographic Services; needed to verify update signatures
    $cryptSvc = Get-Service -Name 'cryptsvc' -ErrorAction SilentlyContinue
    if ($null -ne $cryptSvc -and $cryptSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] cryptsvc service Disabled -- update signature verification will fail"
    }
    else {
        $checks += "  [PASS] cryptsvc service enabled"
    }

    # TrustedInstaller -- Windows Modules Installer; needed to install system updates
    $tiSvc = Get-Service -Name 'TrustedInstaller' -ErrorAction SilentlyContinue
    if ($null -ne $tiSvc -and $tiSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] TrustedInstaller service Disabled -- system updates cannot be installed"
    }
    else {
        $checks += "  [PASS] TrustedInstaller service enabled"
    }

    # dosvc -- Delivery Optimization; Disabled significantly impairs download capability
    $doSvc = Get-Service -Name 'dosvc' -ErrorAction SilentlyContinue
    if ($null -ne $doSvc -and $doSvc.StartType -eq 'Disabled') {
        $checks += "  [FAIL] dosvc service Disabled -- Delivery Optimization unavailable"
    }
    else {
        $checks += "  [PASS] dosvc service enabled"
    }

    $hasBlockers = (
        $noAutoUpdate -eq 1 -or
        $auOptions -eq 1 -or
        $noConnect -eq 1 -or
        $disableUX -eq 1 -or
        $null -ne $disableWUAccess -or
        $disableOSUpgrade -eq 1 -or
        $noWUExplorer -eq 1 -or
        $null -ne $disableWUAltPath -or
        ($null -ne $allowAutoUpdate -and $allowAutoUpdate -eq 0) -or
        ($null -ne $wuSvc  -and $wuSvc.StartType  -eq 'Disabled') -or
        ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') -or
        ($null -ne $medicSvc -and $medicSvc.StartType -eq 'Disabled') -or
        ($null -ne $bitsSvc  -and $bitsSvc.StartType  -eq 'Disabled') -or
        ($null -ne $cryptSvc -and $cryptSvc.StartType -eq 'Disabled') -or
        ($null -ne $tiSvc    -and $tiSvc.StartType    -eq 'Disabled') -or
        ($null -ne $doSvc    -and $doSvc.StartType    -eq 'Disabled')
    )

    # ========================================================================
    #  SECTION 2: SCCM
    # ========================================================================
    $checks += ""
    $checks += "--- SCCM / Co-Management ---"

    $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
    $hasSCCM     = ($null -ne $sccmService -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))

    $wuShiftedToIntune = $false
    if ($hasSCCM) {
        $coMgmtFlags       = Get-SafeRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
        $wuShiftedToIntune = ($null -ne $coMgmtFlags -and ($coMgmtFlags -band 16) -eq 16)
        if ($wuShiftedToIntune) { $hasSCCM = $false }
    }

    if ($hasSCCM) {
        $checks += "  [FAIL] SCCM controlling updates -- WU workload not shifted to Intune"
        $checks += "           HKLM:\SOFTWARE\Microsoft\CCM\CoManagementFlags"
    }
    else {
        $checks += "  [PASS] SCCM not controlling updates"
    }

    # ========================================================================
    #  SECTION 3: POLICY-DRIVEN UPDATE SOURCE
    # ========================================================================
    $checks += ""
    $checks += "--- Update Scan Source (PolicyDrivenSource) ---"

    $srcFeature_GP  = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcFeature_MDM = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_GP  = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcQuality_MDM = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcDriver_GP   = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcDriver_MDM  = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcOther_GP    = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'
    $srcOther_MDM   = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'

    $featureFromWU = ($srcFeature_GP -eq 0 -or $srcFeature_MDM -eq 0)
    $qualityFromWU = ($srcQuality_GP -eq 0 -or $srcQuality_MDM -eq 0)
    $driverFromWU  = ($srcDriver_GP  -eq 0 -or $srcDriver_MDM  -eq 0)
    $otherFromWU   = ($srcOther_GP   -eq 0 -or $srcOther_MDM   -eq 0)

    foreach ($type in @('Feature', 'Quality', 'Driver', 'Other')) {
        $gpVal  = Get-Variable -Name "src${type}_GP"  -ValueOnly
        $mdmVal = Get-Variable -Name "src${type}_MDM" -ValueOnly
        $fromWU = Get-Variable -Name "$($type.ToLower())FromWU" -ValueOnly

        if ($fromWU) {
            $src = if ($mdmVal -eq 0) { $RegPath_MDM } else { $RegPath_WU }
            $checks += "  [PASS] PolicyDrivenSource $type = 0 (WUfB)    ($src)"
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

    $allPolicyDrivenToWU = ($featureFromWU -and $qualityFromWU -and $driverFromWU -and $otherFromWU)

    # ========================================================================
    #  SECTION 4: WSUS ARTIFACTS
    # ========================================================================
    $checks += ""
    $checks += "--- WSUS Artifacts ---"

    $wuServer            = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUServer'
    $wuStatusServer      = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUStatusServer'
    $useWUServer         = Get-SafeRegistryValue -Path $RegPath_AU -Name 'UseWUServer'
    $updateServiceUrlAlt = Get-SafeRegistryValue -Path $RegPath_WU -Name 'UpdateServiceUrlAlternate'
    $targetGroup         = Get-SafeRegistryValue -Path $RegPath_WU -Name 'TargetGroup'
    $targetGroupEnabled  = Get-SafeRegistryValue -Path $RegPath_WU -Name 'TargetGroupEnabled'

    $hasWSUS        = ($useWUServer -eq 1 -and $null -ne $wuServer)
    $hasWSUSArtifacts = ($null -ne $wuServer -or $null -ne $wuStatusServer -or
                         $null -ne $updateServiceUrlAlt -or $null -ne $targetGroup)

    foreach ($artifact in @(
        @{ Name = 'WUServer';               Val = $wuServer;            Path = $RegPath_WU },
        @{ Name = 'WUStatusServer';         Val = $wuStatusServer;      Path = $RegPath_WU },
        @{ Name = 'UpdateServiceUrlAlternate'; Val = $updateServiceUrlAlt; Path = $RegPath_WU },
        @{ Name = 'TargetGroup';            Val = $targetGroup;         Path = $RegPath_WU },
        @{ Name = 'TargetGroupEnabled';     Val = $targetGroupEnabled;  Path = $RegPath_WU },
        @{ Name = 'UseWUServer';            Val = $useWUServer;         Path = $RegPath_AU }
    )) {
        if ($null -ne $artifact.Val) {
            if ($Config_TreatWSUSArtifactsAsFail) {
                $checks += "  [FAIL] $($artifact.Name) present -- WSUS artifact should be removed"
                $checks += "           $($artifact.Path)\$($artifact.Name)"
            }
            else {
                $checks += "  [WARN] $($artifact.Name) present -- WSUS artifact (overridden if PolicyDrivenSource=0)"
                $checks += "           $($artifact.Path)\$($artifact.Name)"
            }
        }
        else {
            $checks += "  [PASS] $($artifact.Name) not present"
        }
    }

    # ========================================================================
    #  SECTION 5: STALE PAUSES
    # ========================================================================
    $checks += ""
    $checks += "--- Stale Pauses ---"

    # Policy-level pauses (GP path) — these block updates when set
    $pauseFeature    = Get-SafeRegistryValue -Path $RegPath_WU -Name 'PauseFeatureUpdates'
    $pauseQuality    = Get-SafeRegistryValue -Path $RegPath_WU -Name 'PauseQualityUpdates'
    $pauseFeatStart  = Get-SafeRegistryValue -Path $RegPath_WU -Name 'PauseFeatureUpdatesStartTime'
    $pauseQualStart  = Get-SafeRegistryValue -Path $RegPath_WU -Name 'PauseQualityUpdatesStartTime'
    $pauseFeatEnd    = Get-SafeRegistryValue -Path $RegPath_WU -Name 'PauseFeatureUpdatesEndTime'
    $pauseQualEnd    = Get-SafeRegistryValue -Path $RegPath_WU -Name 'PauseQualityUpdatesEndTime'

    foreach ($p in @(
        @{ Name = 'PauseFeatureUpdates';          Val = $pauseFeature;   BlockIf = { $args[0] -eq 1 } },
        @{ Name = 'PauseQualityUpdates';          Val = $pauseQuality;   BlockIf = { $args[0] -eq 1 } },
        @{ Name = 'PauseFeatureUpdatesStartTime'; Val = $pauseFeatStart; BlockIf = { $null -ne $args[0] } },
        @{ Name = 'PauseFeatureUpdatesEndTime';   Val = $pauseFeatEnd;   BlockIf = { $null -ne $args[0] } },
        @{ Name = 'PauseQualityUpdatesStartTime'; Val = $pauseQualStart; BlockIf = { $null -ne $args[0] } },
        @{ Name = 'PauseQualityUpdatesEndTime';   Val = $pauseQualEnd;   BlockIf = { $null -ne $args[0] } }
    )) {
        if (& $p.BlockIf $p.Val) {
            $checks += "  [FAIL] $($p.Name) set -- updates paused via policy"
            $checks += "           $RegPath_WU\$($p.Name)"
        }
        else {
            $checks += "  [PASS] $($p.Name) not set"
        }
    }

    # UX-level pause (user-initiated via Settings)
    $uxPauseExpiry = Get-SafeRegistryValue -Path $RegPath_UX -Name 'PauseUpdatesExpiryTime'
    $uxPauseActive = $false
    if ($null -ne $uxPauseExpiry) {
        try {
            $expiryDate = [DateTime]::Parse($uxPauseExpiry)
            if ($expiryDate -gt (Get-Date)) {
                $uxPauseActive = $true
                $checks += "  [FAIL] UX pause active -- updates paused until $expiryDate"
                $checks += "           $RegPath_UX\PauseUpdatesExpiryTime"
            }
            else {
                $checks += "  [PASS] UX pause expired ($expiryDate)"
            }
        }
        catch {
            $checks += "  [PASS] PauseUpdatesExpiryTime present but unparseable"
        }
    }
    else {
        $checks += "  [PASS] No UX-level pause active"
    }

    $hasPauses = (
        $pauseFeature -eq 1 -or $pauseQuality -eq 1 -or
        $null -ne $pauseFeatStart -or $null -ne $pauseQualStart -or
        $null -ne $pauseFeatEnd -or $null -ne $pauseQualEnd -or
        $uxPauseActive
    )

    # ========================================================================
    #  SECTION 6: LEGACY / DUAL-SCAN ARTIFACTS
    # ========================================================================
    $checks += ""
    $checks += "--- Legacy / Dual-Scan Artifacts ---"

    # DeferUpgrade=1 is a legacy Win10 dual-scan trigger; persists after GPO changes
    $deferUpgrade = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DeferUpgrade'
    if ($deferUpgrade -eq 1) {
        $checks += "  [FAIL] DeferUpgrade = 1 -- legacy dual-scan trigger present"
        $checks += "           $RegPath_WU\DeferUpgrade"
    }
    else {
        $checks += "  [PASS] DeferUpgrade not set"
    }

    # Dual-scan condition: WSUS active + WUfB deferrals configured + no PolicyDrivenSource + DisableDualScan not set
    $disableDualScan  = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DisableDualScan'
    $featureDefer_raw = Get-PolicyValue -Name 'DeferFeatureUpdatesPeriodInDays'
    $qualityDefer_raw = Get-PolicyValue -Name 'DeferQualityUpdatesPeriodInDays'
    $hasDeferrals     = ($null -ne $featureDefer_raw -or $null -ne $qualityDefer_raw)
    $dualScanRisk     = ($hasWSUS -and $hasDeferrals -and -not $allPolicyDrivenToWU -and $disableDualScan -ne 1)

    if ($dualScanRisk) {
        $checks += "  [FAIL] Dual-scan risk: WSUS active + WUfB deferrals + PolicyDrivenSource not all 0 + DisableDualScan not set"
        $checks += "           $RegPath_WU\DisableDualScan"
    }
    else {
        $checks += "  [PASS] No dual-scan risk"
    }

    $hasLegacyArtifacts = ($deferUpgrade -eq 1 -or $dualScanRisk)

    # ========================================================================
    #  SECTION 7: GP / LGPO CONFLICT SCAN
    # ========================================================================
    $checks += ""
    $checks += "--- GP / LGPO Policy Conflicts ---"

    $gpConflicts = @()

    if (-not $Config_CheckGPConflicts) {
        $checks += "  [SKIP] GP conflict scan disabled (`$Config_CheckGPConflicts = `$false)"
    }
    else {
        # Values that are expected/managed under the WU GP path (set by remediation or valid WUfB)
        # Anything outside this list is a GP/LGPO value that Intune cannot override via MDMWinsOverGP
        # (MDMWinsOverGP does NOT apply to the Update Policy CSP)
        $expectedWUValues = @(
            # Scan source keys (set by remediation)
            'SetPolicyDrivenUpdateSourceForFeatureUpdates',
            'SetPolicyDrivenUpdateSourceForQualityUpdates',
            'SetPolicyDrivenUpdateSourceForDriverUpdates',
            'SetPolicyDrivenUpdateSourceForOtherUpdates',
            # WUfB policy values (may be set by GPO in hybrid environments; informational)
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
            # Note: blockers (DoNotConnect, SetDisableUXWUAccess, etc.) are NOT in this list
            # because they are already caught in Section 1 with specific messages
        )

        $expectedAUValues = @(
            # Set by remediation
            'UseUpdateClassPolicySource',
            # Standard AU settings managed by WUfB/Intune
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
            # Note: NoAutoUpdate and AUOptions are caught in Section 1
        )

        if (Test-Path $RegPath_WU) {
            try {
                $wuProps = Get-ItemProperty -Path $RegPath_WU -ErrorAction Stop
                $wuProps.PSObject.Properties |
                    Where-Object { $_.Name -notlike 'PS*' } |
                    ForEach-Object {
                        if ($_.Name -notin $expectedWUValues) {
                            $gpConflicts += "$($_.Name) = $($_.Value)  [$RegPath_WU]"
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
                        if ($_.Name -notin $expectedAUValues) {
                            $gpConflicts += "$($_.Name) = $($_.Value)  [$RegPath_AU]"
                        }
                    }
            }
            catch { }
        }

        if ($gpConflicts.Count -gt 0) {
            $checks += "  [FAIL] $($gpConflicts.Count) GP/LGPO conflict(s) found that Intune cannot override:"
            foreach ($c in $gpConflicts) {
                $checks += "           $c"
            }
        }
        else {
            $checks += "  [PASS] No unexpected GP/LGPO values found in WU policy paths"
        }
    }

    # ========================================================================
    #  COLLECT HEALTH DATA (all runs, so all exit paths have context)
    # ========================================================================

    $hasUpdateRing = Test-IntuneUpdateRingDelivered
    $mdmHealth     = Test-MDMEnrollmentHealth
    $scanStatus    = Get-LastWUScanStatus

    # ========================================================================
    #  SECTION 8: UPDATE RING DELIVERY
    # ========================================================================
    $checks += ""
    $checks += "--- Management Channel Health ---"

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

    # ========================================================================
    #  SECTION 9: MDM ENROLLMENT
    # ========================================================================
    if (-not $Config_RequireMDMEnrollment) {
        $checks += "  [SKIP] MDM enrollment check disabled (`$Config_RequireMDMEnrollment = `$false)"
    }
    elseif ($mdmHealth.Enrolled) {
        $providerLabel = if ($mdmHealth.Provider -eq 'WMI_Bridge_SCCM_Server') { 'Co-management bridge' } else { 'Intune direct' }
        $upnDisplay    = if ($mdmHealth.UPN) { ", $($mdmHealth.UPN)" } else { '' }
        $checks += "  [PASS] MDM enrollment active                     ($providerLabel$upnDisplay)"
    }
    else {
        $checks += "  [FAIL] No active MDM enrollment -- device cannot receive WUfB policy"
        $checks += "           HKLM:\SOFTWARE\Microsoft\Enrollments"
    }

    # ========================================================================
    #  SECTION 10: WU SCAN FRESHNESS
    # ========================================================================
    if ($Config_MaxScanAgeDays -le 0) {
        $checks += "  [SKIP] WU scan freshness check disabled (`$Config_MaxScanAgeDays = 0)"
    }
    elseif ($null -eq $scanStatus.AgeDays) {
        $checks += "  [PASS] WU scan age unknown (no history available)"
    }
    elseif ($scanStatus.AgeDays -gt $Config_MaxScanAgeDays) {
        $checks += "  [FAIL] WU scan stale -- $($scanStatus.AgeDays) days ago (threshold: $Config_MaxScanAgeDays)"
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
        $upnDisplay    = if ($mdmHealth.UPN) { " ($($mdmHealth.UPN))" } else { '' }
        $healthLines  += "MDM:            Enrolled via $providerLabel$upnDisplay"
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

    # ========================================================================
    #  COLLECT WUfB POLICY INDICATORS (informational, not compliance gates)
    # ========================================================================

    $featureDefer = Get-PolicyValue -Name 'DeferFeatureUpdatesPeriodInDays'
    $qualityDefer = Get-PolicyValue -Name 'DeferQualityUpdatesPeriodInDays'
    if ($null -ne $featureDefer -and $featureDefer -gt 0) { $indicators += "Feature deferral:       $featureDefer days" }
    if ($null -ne $qualityDefer -and $qualityDefer -gt 0) { $indicators += "Quality deferral:       $qualityDefer days" }

    $targetEnabled  = Get-PolicyValue -Name 'TargetReleaseVersion'
    $targetVersion  = Get-PolicyValue -Name 'TargetReleaseVersionInfo'
    $productVersion = Get-PolicyValue -Name 'ProductVersion'
    $versionDisplay = $null
    if ($targetEnabled -eq 1 -and $null -ne $targetVersion) {
        $versionDisplay = ($productVersion, $targetVersion | Where-Object { $_ }) -join ' '
    }
    elseif ($null -ne $targetEnabled -and $targetEnabled -ne 0 -and $targetEnabled -ne 1) {
        $versionDisplay = ($productVersion, $targetEnabled | Where-Object { $_ }) -join ' '
    }
    if ($versionDisplay) { $indicators += "Version target:         $versionDisplay" }

    $deadlineFeature = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ConfigureDeadlineForFeatureUpdates'
    if ($null -eq $deadlineFeature) { $deadlineFeature = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ComplianceDeadlineForFU' }
    if ($null -eq $deadlineFeature) { $deadlineFeature = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineForFeatureUpdates' }

    $deadlineQuality = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ConfigureDeadlineForQualityUpdates'
    if ($null -eq $deadlineQuality) { $deadlineQuality = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ComplianceDeadline' }
    if ($null -eq $deadlineQuality) { $deadlineQuality = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineForQualityUpdates' }

    $deadlineGrace = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ConfigureDeadlineGracePeriod'
    if ($null -eq $deadlineGrace) { $deadlineGrace = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ComplianceGracePeriod' }
    if ($null -eq $deadlineGrace) { $deadlineGrace = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineGracePeriod' }

    $deadlineGraceFU = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates'
    if ($null -eq $deadlineGraceFU) { $deadlineGraceFU = Get-SafeRegistryValue -Path $RegPath_WU  -Name 'ComplianceGracePeriodForFU' }
    if ($null -eq $deadlineGraceFU) { $deadlineGraceFU = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates' }

    if ($null -ne $deadlineFeature) { $indicators += "Feature deadline:       $deadlineFeature days" }
    if ($null -ne $deadlineQuality) { $indicators += "Quality deadline:       $deadlineQuality days" }
    if ($null -ne $deadlineGrace)   { $indicators += "Grace period:           $deadlineGrace days" }
    if ($null -ne $deadlineGraceFU) { $indicators += "Grace period (feature): $deadlineGraceFU days" }

    $branchLevel   = Get-PolicyValue -Name 'BranchReadinessLevel'
    $previewBuilds = Get-PolicyValue -Name 'ManagePreviewBuilds'
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
    if ($null -ne $previewBuilds) {
        $indicators += "Preview builds:         $(if ($previewBuilds -eq 2) { 'Enabled' } else { 'Disabled' })"
    }

    $excludeDrivers = Get-PolicyValue -Name 'ExcludeWUDriversInQualityUpdate'
    if ($null -ne $excludeDrivers) {
        $indicators += "Driver updates:         $(if ($excludeDrivers -eq 1) { 'Excluded from quality updates' } else { 'Included in quality updates' })"
    }

    # ========================================================================
    #  EVALUATE COMPLIANCE — collect ALL issues
    # ========================================================================

    # Blockers
    if ($hasBlockers) {
        if ($noAutoUpdate -eq 1)    { $issues += 'NoAutoUpdate=1 in AU subkey -- automatic updates disabled' }
        if ($auOptions -eq 1)       { $issues += 'AUOptions=1 in AU subkey -- set to never check for updates' }
        if ($noConnect -eq 1)       { $issues += 'DoNotConnectToWindowsUpdateInternetLocations=1 -- WU server connectivity blocked' }
        if ($disableUX -eq 1)       { $issues += 'SetDisableUXWUAccess=1 -- Windows Update UI/access disabled' }
        if ($null -ne $disableWUAccess) { $issues += "DisableWindowsUpdateAccess=$disableWUAccess -- all Windows Update access blocked" }
        if ($disableOSUpgrade -eq 1) { $issues += 'DisableOSUpgrade=1 -- OS feature update upgrades blocked' }
        if ($noWUExplorer -eq 1)    { $issues += 'NoWindowsUpdate=1 (Explorer policy) -- Windows Update access removed' }
        if ($null -ne $disableWUAltPath) { $issues += "DisableWindowsUpdateAccess=$disableWUAltPath (legacy policy path) -- WU access blocked" }
        if ($null -ne $allowAutoUpdate -and $allowAutoUpdate -eq 0) { $issues += 'AllowAutoUpdate=0 (MDM/CSP) -- automatic updates disabled via Intune CSP' }
        if ($null -ne $wuSvc    -and $wuSvc.StartType    -eq 'Disabled') { $issues += 'wuauserv service startup Disabled -- Windows Update cannot run' }
        if ($null -ne $usoSvc   -and $usoSvc.StartType   -eq 'Disabled') { $issues += 'UsoSvc service startup Disabled -- Update Orchestrator cannot run' }
        if ($null -ne $medicSvc -and $medicSvc.StartType -eq 'Disabled') { $issues += 'WaaSMedicSvc service startup Disabled -- WU self-healing broken' }
        if ($null -ne $bitsSvc  -and $bitsSvc.StartType  -eq 'Disabled') { $issues += 'bits service startup Disabled -- update downloads will fail' }
        if ($null -ne $cryptSvc -and $cryptSvc.StartType -eq 'Disabled') { $issues += 'cryptsvc service startup Disabled -- update signature verification will fail' }
        if ($null -ne $tiSvc    -and $tiSvc.StartType    -eq 'Disabled') { $issues += 'TrustedInstaller service startup Disabled -- system updates cannot be installed' }
        if ($null -ne $doSvc    -and $doSvc.StartType    -eq 'Disabled') { $issues += 'dosvc service startup Disabled -- Delivery Optimization unavailable' }
        $remediation += 'Remove update blockers and re-enable services (remediation script handles this)'
    }

    # SCCM
    if ($hasSCCM) {
        $issues      += 'SCCM/ConfigMgr is managing updates (WU workload not shifted to Intune)'
        $remediation += 'Shift the Windows Update workload to Intune in co-management settings'
    }

    # PolicyDrivenSource
    if (-not $allPolicyDrivenToWU) {
        foreach ($type in @('Feature', 'Quality', 'Driver', 'Other')) {
            $gp  = Get-Variable -Name "src${type}_GP"  -ValueOnly
            $mdm = Get-Variable -Name "src${type}_MDM" -ValueOnly
            if ($null -eq $gp -and $null -eq $mdm) {
                $issues += "$type updates: PolicyDrivenSource not configured (missing from both GP and MDM paths)"
            }
            elseif ($gp -ne 0 -and $mdm -ne 0) {
                $issues += "$type updates: PolicyDrivenSource set to WSUS (value 1), needs WUfB (value 0)"
            }
        }
        if ($hasWSUS) {
            $issues += "WSUS server configured: $wuServer -- will control misconfigured update types"
        }
        $remediation += 'Set all 4 PolicyDrivenSource keys to 0 (remediation script handles this)'
    }

    # WSUS artifacts (FAIL mode)
    if ($Config_TreatWSUSArtifactsAsFail -and $hasWSUSArtifacts) {
        foreach ($name in @('WUServer','WUStatusServer','UpdateServiceUrlAlternate','TargetGroup')) {
            $val = Get-SafeRegistryValue -Path $RegPath_WU -Name $name
            if ($null -ne $val) { $issues += "WSUS artifact present: $name -- should be removed" }
        }
        $remediation += 'Remove WSUS registry artifacts (remediation script handles this)'
    }

    # Pauses
    if ($hasPauses) {
        if ($pauseFeature -eq 1)   { $issues += 'PauseFeatureUpdates=1 -- feature updates paused via policy' }
        if ($pauseQuality -eq 1)   { $issues += 'PauseQualityUpdates=1 -- quality updates paused via policy' }
        if ($null -ne $pauseFeatStart) { $issues += 'PauseFeatureUpdatesStartTime set -- stale feature pause timestamp' }
        if ($null -ne $pauseQualStart) { $issues += 'PauseQualityUpdatesStartTime set -- stale quality pause timestamp' }
        if ($null -ne $pauseFeatEnd)   { $issues += 'PauseFeatureUpdatesEndTime set -- stale feature pause end timestamp' }
        if ($null -ne $pauseQualEnd)   { $issues += 'PauseQualityUpdatesEndTime set -- stale quality pause end timestamp' }
        if ($uxPauseActive)            { $issues += "User-initiated pause active (expires $([DateTime]::Parse($uxPauseExpiry))) -- updates paused via Settings" }
        $remediation += 'Remove stale pause entries (remediation script handles this)'
    }

    # Legacy artifacts
    if ($hasLegacyArtifacts) {
        if ($deferUpgrade -eq 1)  { $issues += 'DeferUpgrade=1 -- legacy dual-scan trigger; should be removed' }
        if ($dualScanRisk)         { $issues += 'Dual-scan risk: WSUS + WUfB deferrals active without PolicyDrivenSource=0 and no DisableDualScan' }
        $remediation += 'Remove legacy dual-scan artifacts (remediation script handles this)'
    }

    # GP conflicts
    if ($Config_CheckGPConflicts -and $gpConflicts.Count -gt 0) {
        foreach ($c in $gpConflicts) {
            $issues += "GP/LGPO conflict (Intune cannot override): $c"
        }
        $remediation += 'Remove conflicting GP/LGPO values from WU policy paths (remediation script handles this)'
    }

    # Update Ring
    if ($Config_RequireUpdateRing -and -not $hasUpdateRing) {
        $issues      += 'No Intune WUfB Update Ring is actively delivering policy to this device'
        $remediation += 'Assign a WUfB Update Ring to this device in Intune'
    }

    # MDM enrollment
    if ($Config_RequireMDMEnrollment -and -not $mdmHealth.Enrolled) {
        $issues      += 'No active Intune MDM enrollment -- device cannot receive WUfB policy'
        $remediation += 'Re-enroll this device in Intune (manual action required)'
    }

    # Scan freshness
    if ($Config_MaxScanAgeDays -gt 0 -and $null -ne $scanStatus.AgeDays -and $scanStatus.AgeDays -gt $Config_MaxScanAgeDays) {
        $issues      += "Windows Update has not scanned in $($scanStatus.AgeDays) days (threshold: $Config_MaxScanAgeDays)"
        $remediation += 'Investigate why the WU client is not scanning (manual action required)'
    }

    # ========================================================================
    #  OUTPUT
    # ========================================================================

    if ($issues.Count -gt 0) {
        $reason = "$($issues.Count) issue$(if ($issues.Count -gt 1) { 's' }) found -- device is not WUfB compliant"
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

    $notes = @()
    if ($hasWSUSArtifacts -and -not $Config_TreatWSUSArtifactsAsFail) {
        $notes += "Stale WSUS config present but fully overridden by PolicyDrivenSource=0 -- WUfB is in control"
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
    $msg = Format-Output -Result 'ERROR' -Reason "Detection failed -- $($_.Exception.Message)"
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output $msg
    exit 1
}
