#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Detection Script - Checks if device is managed by Windows Update for Business.

.DESCRIPTION
    Intune Proactive Remediation detection script.
    Determines whether the device is receiving updates via WUfB (compliant)
    or another source such as WSUS, SCCM, or no policy at all (non-compliant).

    Exit 0 = WUfB detected (compliant, no remediation needed)
    Exit 1 = WUfB not detected (non-compliant, triggers remediation)

.NOTES
    Author:  Device-DNA Project
    Tool:    WUDUP Detection v1.0.0
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

# ============================================================================
#  DETECTION LOGIC
# ============================================================================

try {
    # Gather key indicators
    $featureDefer_GP  = Get-RegValue -Path $RegPath_WU -Name 'DeferFeatureUpdatesPeriodInDays'
    $qualityDefer_GP  = Get-RegValue -Path $RegPath_WU -Name 'DeferQualityUpdatesPeriodInDays'
    $featureDefer_MDM = Get-RegValue -Path $RegPath_MDM -Name 'DeferFeatureUpdatesPeriodInDays'
    $qualityDefer_MDM = Get-RegValue -Path $RegPath_MDM -Name 'DeferQualityUpdatesPeriodInDays'
    $wuServer         = Get-RegValue -Path $RegPath_WU -Name 'WUServer'
    $useWUServer      = Get-RegValue -Path $RegPath_AU -Name 'UseWUServer'

    $hasDeferrals = ($null -ne $featureDefer_GP -or $null -ne $qualityDefer_GP -or
                     $null -ne $featureDefer_MDM -or $null -ne $qualityDefer_MDM)
    $hasWSUS = ($useWUServer -eq 1 -and $null -ne $wuServer)

    # WUfB = deferral policies present WITHOUT active WSUS
    if ($hasDeferrals -and -not $hasWSUS) {
        $featureDays = if ($null -ne $featureDefer_GP) { $featureDefer_GP } else { $featureDefer_MDM }
        $qualityDays = if ($null -ne $qualityDefer_GP) { $qualityDefer_GP } else { $qualityDefer_MDM }
        Write-Output "COMPLIANT: WUfB detected. Feature deferral: ${featureDays}d, Quality deferral: ${qualityDays}d"
        exit 0
    }

    # Not WUfB — report why
    if ($hasWSUS) {
        Write-Output "NON-COMPLIANT: Device is using WSUS ($wuServer), not WUfB."
    }
    elseif ($hasDeferrals -and $hasWSUS) {
        Write-Output "NON-COMPLIANT: Dual-scan state detected (WSUS + deferrals). Not clean WUfB."
    }
    else {
        # Check if SCCM is present
        $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
        $ccmKey = Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'
        if ($null -ne $sccmService -and $ccmKey) {
            Write-Output "NON-COMPLIANT: Device is managed by SCCM/ConfigMgr. No WUfB deferrals set."
        }
        else {
            Write-Output "NON-COMPLIANT: No WUfB deferral policies detected. Device using default Windows Update."
        }
    }
    exit 1
}
catch {
    Write-Output "ERROR: Detection failed - $($_.Exception.Message)"
    exit 1
}
