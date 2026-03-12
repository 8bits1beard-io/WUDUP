#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Detection Script - Checks if device is managed by Windows Update for Business.

.DESCRIPTION
    Intune Proactive Remediation detection script.
    Determines whether the device is receiving updates via WUfB (compliant)
    or another source such as WSUS, SCCM, or no policy at all (non-compliant).

    Checks all WUfB indicator registry locations:
    - Deferral policies (GP and MDM paths)
    - SetPolicyDrivenUpdateSourceFor* keys (Windows 10 2004+ / Windows 11)
    - Version targeting (TargetReleaseVersion / ProductVersion)
    - Compliance deadlines (ConfigureDeadlineForFeature/QualityUpdates)
    - Channel targeting (BranchReadinessLevel)
    - Preview build management (ManagePreviewBuilds)

    Handles split-source scenarios where WSUS is configured but WUfB
    controls feature/quality updates via SetPolicyDrivenUpdateSource keys.

    Exit 0 = WUfB detected (compliant, no remediation needed)
    Exit 1 = WUfB not detected (non-compliant, triggers remediation)

.NOTES
    Author:  Device-DNA Project
    Tool:    WUDUP Detection v1.1.0
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  REGISTRY PATHS
# ============================================================================

$RegPath_WU  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$RegPath_MDM = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'

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

# Reads a value from GP path first, then MDM path as fallback
function Get-PolicyValue {
    param([string]$Name)
    $val = Get-RegValue -Path $RegPath_WU -Name $Name
    if ($null -ne $val) { return $val }
    return Get-RegValue -Path $RegPath_MDM -Name $Name
}

# ============================================================================
#  DETECTION LOGIC
# ============================================================================

try {
    $indicators = @()

    # --- 1. Policy-Driven Update Source (most definitive, Windows 10 2004+) ---
    $srcFeature_GP  = Get-RegValue -Path $RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_GP  = Get-RegValue -Path $RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcFeature_MDM = Get-RegValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_MDM = Get-RegValue -Path $RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'

    # Value 0 = Windows Update (WUfB), Value 1 = WSUS
    $featureFromWU = ($srcFeature_GP -eq 0 -or $srcFeature_MDM -eq 0)
    $qualityFromWU = ($srcQuality_GP -eq 0 -or $srcQuality_MDM -eq 0)

    if ($featureFromWU) { $indicators += 'PolicyDrivenSource: Feature updates from WU' }
    if ($qualityFromWU) { $indicators += 'PolicyDrivenSource: Quality updates from WU' }

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
    $deadlineFeature = Get-PolicyValue -Name 'ConfigureDeadlineForFeatureUpdates'
    $deadlineQuality = Get-PolicyValue -Name 'ConfigureDeadlineForQualityUpdates'

    if ($null -ne $deadlineFeature) { $indicators += "FeatureDeadline: ${deadlineFeature}d" }
    if ($null -ne $deadlineQuality) { $indicators += "QualityDeadline: ${deadlineQuality}d" }

    # --- 5. Channel / Preview Build Management ---
    $branchLevel = Get-PolicyValue -Name 'BranchReadinessLevel'
    $previewBuilds = Get-PolicyValue -Name 'ManagePreviewBuilds'

    if ($null -ne $branchLevel) { $indicators += "BranchReadiness: $branchLevel" }
    if ($null -ne $previewBuilds) { $indicators += "PreviewBuilds: $previewBuilds" }

    # --- 6. WSUS Configuration ---
    $wuServer    = Get-RegValue -Path $RegPath_WU -Name 'WUServer'
    $useWUServer = Get-RegValue -Path $RegPath_AU -Name 'UseWUServer'
    $hasWSUS     = ($useWUServer -eq 1 -and $null -ne $wuServer)

    # --- 7. SCCM Detection ---
    $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
    $hasSCCM     = ($null -ne $sccmService -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))

    # ========================================================================
    #  EVALUATE COMPLIANCE
    # ========================================================================

    $hasWUfBIndicators = ($indicators.Count -gt 0)

    # Split-source: WSUS is configured but PolicyDrivenSource directs feature/quality to WU
    $isSplitSource = ($hasWSUS -and ($featureFromWU -or $qualityFromWU))

    if ($hasWUfBIndicators -and (-not $hasWSUS -or $isSplitSource)) {
        # WUfB is managing updates (either exclusively or via split-source)
        $detail = $indicators -join '; '
        if ($isSplitSource) {
            Write-Output "COMPLIANT: WUfB detected (split-source with WSUS). $detail"
        }
        else {
            Write-Output "COMPLIANT: WUfB detected. $detail"
        }
        exit 0
    }

    # Not WUfB — report why
    if ($hasWSUS -and $hasWUfBIndicators) {
        # WSUS active with WUfB indicators but no PolicyDrivenSource override — dual-scan risk
        Write-Output "NON-COMPLIANT: Dual-scan state (WSUS at $wuServer + WUfB policies). No PolicyDrivenSource override."
    }
    elseif ($hasWSUS) {
        Write-Output "NON-COMPLIANT: Device is using WSUS ($wuServer), no WUfB policies detected."
    }
    elseif ($hasSCCM) {
        Write-Output "NON-COMPLIANT: Device is managed by SCCM/ConfigMgr. No WUfB policies detected."
    }
    else {
        Write-Output "NON-COMPLIANT: No WUfB policies detected. Device using default Windows Update."
    }
    exit 1
}
catch {
    Write-Output "ERROR: Detection failed - $($_.Exception.Message)"
    exit 1
}
