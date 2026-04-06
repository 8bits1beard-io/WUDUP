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
#  COLOR SUPPORT
# ============================================================================
# ANSI colors are only emitted when the host can render them AND the session is
# interactive AND we're not running as SYSTEM. Intune Proactive Remediations run
# as SYSTEM in a non-interactive session 0 — colors stay off there so the portal
# shows clean plain text instead of escape-code garbage. PS 5.1 compatible.

$script:IsSystem = $false
$script:UseColor = $false
try {
    $vtOk     = [bool]$Host.UI.SupportsVirtualTerminal
    $interact = [Environment]::UserInteractive
    $script:IsSystem = ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
    if ($vtOk -and $interact -and -not $script:IsSystem) { $script:UseColor = $true }
}
catch { }

$ESC = [char]27
$script:ColorReset = if ($script:UseColor) { "$ESC[0m" }      else { '' }
$script:ColorPass  = if ($script:UseColor) { "$ESC[32m" }     else { '' }  # green
$script:ColorFail  = if ($script:UseColor) { "$ESC[31m" }     else { '' }  # red
$script:ColorSkip  = if ($script:UseColor) { "$ESC[33m" }     else { '' }  # yellow
$script:ColorBold  = if ($script:UseColor) { "$ESC[1m" }      else { '' }

function Colorize-Status {
    param([string]$Status)
    $c = switch ($Status) {
        'PASS' { $script:ColorPass }
        'FAIL' { $script:ColorFail }
        'SKIP' { $script:ColorSkip }
        default { '' }
    }
    return "$c[$Status]$script:ColorReset"
}

function Colorize-Result {
    param([string]$Result)
    $c = switch ($Result) {
        'COMPLIANT'     { $script:ColorPass }
        'NON-COMPLIANT' { $script:ColorFail }
        'ERROR'         { $script:ColorFail }
        default { '' }
    }
    return "$script:ColorBold$c$Result$script:ColorReset"
}

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

$script:LogFilePath = Join-Path $env:ProgramData 'WUDUP\Logs\detect.log'

function Write-Log {
    param([string]$Message)
    try {
        $logDir = Split-Path $script:LogFilePath -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Add-Content -Path $script:LogFilePath -Value "[$timestamp] $Message" -ErrorAction SilentlyContinue
    }
    catch { }
}

# Writes the FULL verbose detection report to the log file with a clean separator.
# Always called regardless of output mode so the device retains the complete report.
function Write-LogReport {
    param([string]$Report)
    try {
        $logDir = Split-Path $script:LogFilePath -Parent
        if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
        $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $separator = "`n----- [$timestamp] -----"
        Add-Content -Path $script:LogFilePath -Value $separator -ErrorAction SilentlyContinue
        Add-Content -Path $script:LogFilePath -Value $Report -ErrorAction SilentlyContinue
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
    $lines += "$(Colorize-Result $Result) — $Reason"

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

# Compact output for Intune Proactive Remediation portal display.
# Intune's Output column truncates at ~2 KB and is narrow — verbose multi-line
# blocks for every check make it impossible to spot what actually failed. This
# format leads with the result, lists ONLY failed checks (one per line), gives
# a one-line health summary, and points to the log file for the full report.
# Used automatically when running as SYSTEM (Intune context).
function Format-CompactOutput {
    param(
        [string]$Result,           # COMPLIANT / NON-COMPLIANT / ERROR
        [string]$Reason,           # One-line summary
        [array]$FailedChecks,      # PSCustomObjects with Number/Name/Current
        [string]$HealthOneLine,    # Single-line health summary
        [string]$LogPath           # Where to find the full report
    )
    $lines = @()
    $lines += "$Result - $Reason"

    if ($FailedChecks -and $FailedChecks.Count -gt 0) {
        $lines += ""
        foreach ($fc in $FailedChecks) {
            $num = '{0:D2}' -f $fc.Number
            $lines += "[$num] $($fc.Name): $($fc.Current)"
        }
    }

    if ($HealthOneLine) {
        $lines += ""
        $lines += "Health: $HealthOneLine"
    }

    if ($LogPath) {
        $lines += "Full report: $LogPath"
    }

    return ($lines -join "`n")
}

# Formats a registry value for display: $null -> <not set>, '' -> <empty>, else stringified.
function Format-Val {
    param($Value)
    if ($null -eq $Value) { return '<not set>' }
    if ($Value -is [string] -and $Value -eq '') { return '<empty>' }
    return "$Value"
}

# Builds a numbered check entry. Returns an array of strings to append to $checks.
# Status: PASS / FAIL / SKIP
function Add-Check {
    param(
        [string]$Name,
        $CurrentValue,
        [string]$ExpectedValue,
        [string]$Status,
        [string]$Path = $null
    )
    $script:checkNum++
    $num = '{0:D2}' -f $script:checkNum
    $cur = Format-Val $CurrentValue
    if ($Status -eq 'FAIL') {
        $script:FailedChecks += [PSCustomObject]@{
            Number  = $script:checkNum
            Name    = $Name
            Current = $cur
        }
    }
    $statusTag = Colorize-Status $Status
    $lines = @()
    $lines += "  [$num] $statusTag $Name"
    $lines += "         Current:  $cur"
    $lines += "         Expected: $ExpectedValue"
    if ($Path) { $lines += "         Path:     $Path" }
    return $lines
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
    $script:checkNum = 0
    $script:FailedChecks = @()

    # --- 1. Update Blocker Checks ---
    $noAutoUpdate = Get-SafeRegistryValue -Path $RegPath_AU -Name 'NoAutoUpdate'
    $checks += Add-Check -Name 'NoAutoUpdate (1 = automatic updates disabled)' `
        -CurrentValue $noAutoUpdate -ExpectedValue '<not set> or 0' `
        -Status $(if ($noAutoUpdate -eq 1) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_AU\NoAutoUpdate"

    $auOptions = Get-SafeRegistryValue -Path $RegPath_AU -Name 'AUOptions'
    $checks += Add-Check -Name 'AUOptions (1 = Never check for updates)' `
        -CurrentValue $auOptions -ExpectedValue '<not set> or != 1' `
        -Status $(if ($auOptions -eq 1) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_AU\AUOptions"

    $noConnect = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    $checks += Add-Check -Name 'DoNotConnectToWindowsUpdateInternetLocations (1 = WU servers blocked)' `
        -CurrentValue $noConnect -ExpectedValue '<not set> or 0' `
        -Status $(if ($noConnect -eq 1) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_WU\DoNotConnectToWindowsUpdateInternetLocations"

    $disableUX = Get-SafeRegistryValue -Path $RegPath_WU -Name 'SetDisableUXWUAccess'
    $checks += Add-Check -Name 'SetDisableUXWUAccess (1 = WU UI/access disabled)' `
        -CurrentValue $disableUX -ExpectedValue '<not set> or 0' `
        -Status $(if ($disableUX -eq 1) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_WU\SetDisableUXWUAccess"

    # Separate from SetDisableUXWUAccess — Microsoft Autopatch checks for this specifically
    $disableWUAccess = Get-SafeRegistryValue -Path $RegPath_WU -Name 'DisableWindowsUpdateAccess'
    $checks += Add-Check -Name 'DisableWindowsUpdateAccess (1 = all WU features turned off)' `
        -CurrentValue $disableWUAccess -ExpectedValue '<not set> or 0' `
        -Status $(if ($disableWUAccess -eq 1) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_WU\DisableWindowsUpdateAccess"

    $mdmAllowAutoUpdate = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'AllowAutoUpdate'
    $checks += Add-Check -Name 'MDM AllowAutoUpdate (5 = auto updates disabled via Intune)' `
        -CurrentValue $mdmAllowAutoUpdate -ExpectedValue '<not set> or != 5' `
        -Status $(if ($mdmAllowAutoUpdate -eq 5) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_MDM\AllowAutoUpdate"

    $mdmAllowUpdateService = Get-SafeRegistryValue -Path $RegPath_MDM -Name 'AllowUpdateService'
    $checks += Add-Check -Name 'MDM AllowUpdateService (0 = all update services blocked via Intune)' `
        -CurrentValue $mdmAllowUpdateService -ExpectedValue '<not set> or != 0' `
        -Status $(if ($mdmAllowUpdateService -eq 0) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_MDM\AllowUpdateService"

    $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    $wuSvcStartVal = if ($null -ne $wuSvc) { "$($wuSvc.StartType)" } else { '<service not found>' }
    $checks += Add-Check -Name 'wuauserv service startup type' `
        -CurrentValue $wuSvcStartVal -ExpectedValue 'Manual or Automatic (not Disabled)' `
        -Status $(if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') { 'FAIL' } else { 'PASS' }) `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv\Start'

    $usoSvc = Get-Service -Name 'UsoSvc' -ErrorAction SilentlyContinue
    $usoSvcStartVal = if ($null -ne $usoSvc) { "$($usoSvc.StartType)" } else { '<service not found>' }
    $checks += Add-Check -Name 'UsoSvc (Update Orchestrator) service startup type' `
        -CurrentValue $usoSvcStartVal -ExpectedValue 'Manual or Automatic (not Disabled)' `
        -Status $(if ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') { 'FAIL' } else { 'PASS' }) `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc\Start'

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

    # Check co-management: if the WU workload is shifted to Intune (CoManagementFlags bit 4 = 16),
    # SCCM no longer controls updates — evaluate as Intune-managed instead.
    $wuShiftedToIntune = $false
    $coMgmtFlags = $null
    if ($hasSCCM) {
        $coMgmtFlags = Get-SafeRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
        $wuShiftedToIntune = ($null -ne $coMgmtFlags -and ($coMgmtFlags -band 16) -eq 16)
        if ($wuShiftedToIntune) {
            $hasSCCM = $false
        }
    }

    $sccmCurrent = if ($null -eq $sccmService) {
        'SCCM not present'
    } elseif ($wuShiftedToIntune) {
        "SCCM present, WU workload shifted to Intune (CoManagementFlags=$coMgmtFlags, bit 4 set)"
    } else {
        "SCCM controlling updates (CoManagementFlags=$(Format-Val $coMgmtFlags), bit 4 NOT set)"
    }
    $checks += Add-Check -Name 'SCCM update management' `
        -CurrentValue $sccmCurrent -ExpectedValue 'Not present, OR co-managed with WU workload shifted to Intune (CoManagementFlags bit 4 set)' `
        -Status $(if ($hasSCCM) { 'FAIL' } else { 'PASS' }) `
        -Path 'HKLM:\SOFTWARE\Microsoft\CCM\CoManagementFlags'

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

    # Build per-type check lines showing GP and MDM values side-by-side
    foreach ($type in @('Feature','Quality','Driver','Other')) {
        $gpVal  = Get-Variable -Name "src${type}_GP" -ValueOnly
        $mdmVal = Get-Variable -Name "src${type}_MDM" -ValueOnly
        $fromWU = Get-Variable -Name "$($type.ToLower())FromWU" -ValueOnly

        $current = "GP=$(Format-Val $gpVal), MDM=$(Format-Val $mdmVal)"
        $checks += Add-Check -Name "SetPolicyDrivenUpdateSourceFor${type}Updates" `
            -CurrentValue $current -ExpectedValue '0 (Windows Update) on GP path OR MDM path' `
            -Status $(if ($fromWU) { 'PASS' } else { 'FAIL' }) `
            -Path "GP: $RegPath_WU  |  MDM: $RegPath_MDM"
    }

    # --- 4. WSUS Configuration ---
    $wuServer       = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUServer'
    $wuStatusServer = Get-SafeRegistryValue -Path $RegPath_WU -Name 'WUStatusServer'
    $useWUServer    = Get-SafeRegistryValue -Path $RegPath_AU -Name 'UseWUServer'
    $hasWSUS        = ($useWUServer -eq 1 -and $null -ne $wuServer)

    # Orphaned UseWUServer=1 without a valid WUServer — WU client points at nothing
    $orphanedUseWUServer = ($useWUServer -eq 1 -and ($null -eq $wuServer -or $wuServer -eq ''))
    $wsusCurrent = "UseWUServer=$(Format-Val $useWUServer), WUServer=$(Format-Val $wuServer)"
    $checks += Add-Check -Name 'WSUS pointer integrity (UseWUServer + WUServer pair)' `
        -CurrentValue $wsusCurrent -ExpectedValue 'Both unset, OR both set together (no orphan)' `
        -Status $(if ($orphanedUseWUServer) { 'FAIL' } else { 'PASS' }) `
        -Path "$RegPath_AU\UseWUServer"
    if ($orphanedUseWUServer) { $hasBlockers = $true }

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
        $checks += Add-Check -Name 'Intune Update Ring delivery' `
            -CurrentValue 'check skipped' `
            -ExpectedValue 'Set $Config_RequireUpdateRing = $true to enforce' `
            -Status 'SKIP'
    }
    else {
        $checks += Add-Check -Name 'Intune Update Ring delivery' `
            -CurrentValue $(if ($hasUpdateRing) { 'Active (WUfB values found under provider)' } else { 'Not detected' }) `
            -ExpectedValue 'Active — WUfB values delivered via PolicyManager Providers path' `
            -Status $(if ($hasUpdateRing) { 'PASS' } else { 'FAIL' }) `
            -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\<GUID>\default\device\Update'
    }

    # --- 7. MDM enrollment ---
    if (-not $Config_RequireMDMEnrollment) {
        $checks += Add-Check -Name 'MDM enrollment health' `
            -CurrentValue 'check skipped' `
            -ExpectedValue 'Set $Config_RequireMDMEnrollment = $true to enforce' `
            -Status 'SKIP'
    }
    else {
        $mdmCurrent = if ($mdmHealth.Enrolled) {
            $providerLabel = if ($mdmHealth.Provider -eq 'WMI_Bridge_SCCM_Server') { 'Co-management bridge' } else { 'Intune direct' }
            $upnDisplay = if ($mdmHealth.UPN) { " ($($mdmHealth.UPN))" } else { '' }
            "Enrolled via $providerLabel$upnDisplay"
        } else {
            'Not enrolled (no enrollment with EnrollmentState=1)'
        }
        $checks += Add-Check -Name 'MDM enrollment health' `
            -CurrentValue $mdmCurrent `
            -ExpectedValue 'Enrolled (EnrollmentState=1, ProviderID = MS DM Server or WMI_Bridge_SCCM_Server)' `
            -Status $(if ($mdmHealth.Enrolled) { 'PASS' } else { 'FAIL' }) `
            -Path 'HKLM:\SOFTWARE\Microsoft\Enrollments\<GUID>'
    }

    # --- 8. WU scan freshness ---
    if ($Config_MaxScanAgeDays -le 0) {
        $checks += Add-Check -Name 'WU scan freshness' `
            -CurrentValue 'check skipped' `
            -ExpectedValue 'Set $Config_MaxScanAgeDays > 0 to enforce' `
            -Status 'SKIP'
    }
    else {
        $scanCurrent = if ($null -eq $scanStatus.AgeDays) { 'Unknown (no scan history available)' }
                       else { "$($scanStatus.AgeDays) days ago" }
        $scanPass = ($null -eq $scanStatus.AgeDays) -or ($scanStatus.AgeDays -le $Config_MaxScanAgeDays)
        $checks += Add-Check -Name 'WU scan freshness (last successful scan)' `
            -CurrentValue $scanCurrent `
            -ExpectedValue "<= $Config_MaxScanAgeDays days" `
            -Status $(if ($scanPass) { 'PASS' } else { 'FAIL' })
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

    # --- Build a single-line health summary for the compact (Intune) output ---
    $ringPart = "Ring=$(if ($hasUpdateRing) { 'Active' } else { 'None' })"
    $mdmPart  = if ($mdmHealth.Enrolled) {
        $p = if ($mdmHealth.Provider -eq 'WMI_Bridge_SCCM_Server') { 'CoMgmt' } else { 'Intune' }
        "MDM=$p"
    } else { 'MDM=None' }
    $scanPart = if ($null -ne $scanStatus.AgeDays) { "Scan=$($scanStatus.AgeDays)d" } else { 'Scan=?' }
    $rebootPart = "Reboot=$(if ($pendingReboot) { 'Yes' } else { 'No' })"
    $compactHealth = "$ringPart | $mdmPart | $scanPart | $rebootPart"

    # --- Output result ---
    if ($issues.Count -gt 0) {
        $reason = "$($issues.Count) issue$(if ($issues.Count -gt 1) { 's' }) found"
        $verboseMsg = Format-Output -Result 'NON-COMPLIANT' `
            -Reason "$reason — device is not WUfB compliant" `
            -Checks $checks `
            -Issues $issues `
            -Remediation $remediation `
            -Health $healthLines `
            -Policy $indicators
        $compactMsg = Format-CompactOutput -Result 'NON-COMPLIANT' `
            -Reason $reason `
            -FailedChecks $script:FailedChecks `
            -HealthOneLine $compactHealth `
            -LogPath $script:LogFilePath
        # Always log the full verbose report for on-device troubleshooting
        Write-LogReport -Report $verboseMsg
        # Intune (SYSTEM) gets the compact form; interactive runs get the verbose form
        if ($script:IsSystem) { Write-Output $compactMsg } else { Write-Output $verboseMsg }
        exit 1
    }

    # --- Compliant ---
    $notes = @()
    if ($hasWSUS) {
        $notes += "Stale WSUS config present ($wuServer) but fully overridden — WUfB is in control"
    }
    $verboseMsg = Format-Output -Result 'COMPLIANT' `
        -Reason 'WUfB is managing all update types on this device' `
        -Checks $checks `
        -Issues $notes `
        -Health $healthLines `
        -Policy $indicators
    $compactMsg = Format-CompactOutput -Result 'COMPLIANT' `
        -Reason 'WUfB managing all updates' `
        -FailedChecks @() `
        -HealthOneLine $compactHealth `
        -LogPath $script:LogFilePath
    Write-LogReport -Report $verboseMsg
    if ($script:IsSystem) { Write-Output $compactMsg } else { Write-Output $verboseMsg }
    exit 0
}
catch {
    $errMsg = "ERROR - Detection failed: $($_.Exception.Message)"
    Write-Log $errMsg
    # Errors are always short — same in both modes
    Write-Output $errMsg
    exit 1
}
