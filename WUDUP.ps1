#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP - Windows Update Dashboard: Unified Provisioning

.DESCRIPTION
    Performs a thorough discovery of Windows Update configuration on Windows 10/11.
    Detects the management authority (SCCM, Intune/MDM, WSUS, Group Policy, or Local),
    reads all relevant policy and settings registry keys, and displays a color-coded
    dashboard. Optionally allows modification of settings when run as Administrator.

    Compatible with PowerShell 5.1 and PowerShell 7+.

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP v1.4.0
    Created: 12 March 2026
    Requires: Windows 10 or Windows 11, Administrator for modifications
#>

param(
    [switch]$Report
)

# ============================================================================
#  REGISTRY PATH CONSTANTS
# ============================================================================

$script:RegPath_WU        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$script:RegPath_AU        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$script:RegPath_MDM       = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
$script:RegPath_UX        = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$script:RegPath_Pause     = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings'
$script:RegPath_DO_Policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
$script:RegPath_DO_MDM    = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization'
$script:RegPath_NTCur        = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$script:RegPath_Enrollments  = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
$script:RegPath_WUAutoUpdate = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
$script:RegPath_CBS          = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'

# ============================================================================
#  LOOKUP TABLES
# ============================================================================

$script:AUOptionsMap = @{
    1 = 'Disabled (AU is off)'
    2 = 'Notify before download'
    3 = 'Auto download, notify to install'
    4 = 'Auto download and schedule install'
    5 = 'Allow local admin to choose (not valid on Windows 10+)'
    7 = 'Notify for install and notify for restart (Server 2016+ only)'
}

$script:DODownloadModeMap = @{
    0   = 'HTTP only (no peering)'
    1   = 'LAN (peers on same NAT)'
    2   = 'Group (AD site / domain)'
    3   = 'Internet (LAN + Internet peers)'
    99  = 'Simple (no peering, no BITS)'
    100 = 'Bypass (BITS only, no DO)'
}

$script:InstallDayMap = @{
    0 = 'Every day'
    1 = 'Sunday'; 2 = 'Monday'; 3 = 'Tuesday'; 4 = 'Wednesday'
    5 = 'Thursday'; 6 = 'Friday'; 7 = 'Saturday'
}

# ============================================================================
#  HELPER FUNCTIONS
# ============================================================================

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeRegistryValue {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name
    )
    try {
        if (Test-Path -Path $Path) {
            $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $item.$Name
        }
    }
    catch { }
    return $null
}

function Get-AllRegistryValues {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    $result = [ordered]@{}
    if (Test-Path -Path $Path) {
        $props = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($null -ne $props) {
            $props.PSObject.Properties | Where-Object {
                $_.Name -notlike 'PS*'
            } | ForEach-Object {
                $result[$_.Name] = $_.Value
            }
        }
    }
    return $result
}

function Get-RegistryValuesWithType {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    $result = [ordered]@{}
    if (-not (Test-Path -Path $Path)) { return $result }
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        foreach ($name in $key.GetValueNames()) {
            try {
                $kind = $key.GetValueKind($name)
                if ($kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                    # Read raw unexpanded string so the literal %VAR% text is preserved
                    $data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                }
                else {
                    $data = $key.GetValue($name)
                }
                if ($kind -eq [Microsoft.Win32.RegistryValueKind]::Binary) {
                    $data = [Convert]::ToBase64String([byte[]]$data)
                }
                $result[$name] = [ordered]@{ Type = $kind.ToString(); Data = $data }
            }
            catch { }
        }
    }
    catch { }
    return $result
}

function Test-ActiveMDMEnrollment {
    if (-not (Test-Path $script:RegPath_Enrollments)) { return $null }
    try {
        $subkeys = Get-ChildItem -Path $script:RegPath_Enrollments -ErrorAction SilentlyContinue
        foreach ($key in $subkeys) {
            $state = Get-SafeRegistryValue -Path $key.PSPath -Name 'EnrollmentState'
            $provider = Get-SafeRegistryValue -Path $key.PSPath -Name 'ProviderID'
            if ($state -eq 1 -and $null -ne $provider -and $provider -ne '') {
                return $provider
            }
        }
    }
    catch { }
    return $null
}

function Get-WUServiceState {
    $result = [PSCustomObject]@{
        Status         = 'Unknown'
        StartType      = 'Unknown'
        UsoStatus      = 'Unknown'
        UsoStartType   = 'Unknown'
    }
    try {
        $svc = Get-Service -Name 'wuauserv' -ErrorAction Stop
        $result.Status = $svc.Status.ToString()
        $result.StartType = $svc.StartType.ToString()
    }
    catch { }
    try {
        $uso = Get-Service -Name 'UsoSvc' -ErrorAction Stop
        $result.UsoStatus = $uso.Status.ToString()
        $result.UsoStartType = $uso.StartType.ToString()
    }
    catch { }
    return $result
}

function Get-UpdateStatus {
    # Primary: COM API -- same source the Settings app uses
    $rebootCOM = $false
    try {
        $sysInfo = New-Object -ComObject Microsoft.Update.SystemInfo
        $rebootCOM = [bool]$sysInfo.RebootRequired
    }
    catch { }

    # Secondary: registry keys for supplemental detail
    $rebootWUReg = Test-Path "$script:RegPath_WUAutoUpdate\RebootRequired"
    $rebootCBS   = Test-Path "$script:RegPath_CBS\RebootPending"

    $lastInstall = Get-SafeRegistryValue -Path "$script:RegPath_WUAutoUpdate\Results\Install" -Name 'LastSuccessTime'
    $lastDetect  = Get-SafeRegistryValue -Path "$script:RegPath_WUAutoUpdate\Results\Detect" -Name 'LastSuccessTime'
    return [PSCustomObject]@{
        RebootRequired      = $rebootCOM      # Authoritative -- matches Settings app
        RebootRequiredWUReg = $rebootWUReg     # WU registry flag (supplemental)
        RebootRequiredCBS   = $rebootCBS       # CBS flag (often stale)
        LastInstallTime     = $lastInstall
        LastDetectTime      = $lastDetect
    }
}

function Get-RecentUpdateHistory {
    param([int]$Count = 10)
    $history = @()
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $total = $searcher.GetTotalHistoryCount()
        if ($total -gt 0) {
            $limit = [Math]::Min($Count, $total)
            $entries = $searcher.QueryHistory(0, $limit)
            foreach ($entry in $entries) {
                $history += [PSCustomObject]@{
                    Date      = $entry.Date
                    Title     = $entry.Title
                    Operation = switch ($entry.Operation) { 1 { 'Install' } 2 { 'Uninstall' } default { 'Unknown' } }
                    Result    = switch ($entry.ResultCode) { 0 { 'Not Started' } 1 { 'In Progress' } 2 { 'Succeeded' } 3 { 'Succeeded (Errors)' } 4 { 'Failed' } 5 { 'Aborted' } default { 'Unknown' } }
                }
            }
        }
    }
    catch { }
    return $history
}

function Get-RegisteredUpdateServices {
    $services = @()
    try {
        $sm = New-Object -ComObject Microsoft.Update.ServiceManager
        foreach ($svc in $sm.Services) {
            $services += [PSCustomObject]@{
                Name              = $svc.Name
                ServiceID         = $svc.ServiceID
                IsDefaultAUService = $svc.IsDefaultAUService
                IsManaged         = $svc.IsManaged
                ServiceUrl        = $svc.ServiceUrl
            }
        }
    }
    catch { }
    return $services
}

function Ensure-RegistryPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
}

# ============================================================================
#  GET-OSINFO
# ============================================================================

function Get-OSInfo {
    $ntReg = Get-AllRegistryValues -Path $script:RegPath_NTCur

    # Use CIM for Caption (correctly reports "Windows 11" unlike registry ProductName)
    $caption = 'Unknown'
    $arch = 'Unknown'
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $caption = $os.Caption
        $arch = $os.OSArchitecture
    }
    catch {
        # Fallback to registry
        $caption = $ntReg['ProductName']
        if ($null -eq $caption) { $caption = 'Unknown' }
    }

    $displayVersion = $ntReg['DisplayVersion']
    if ($null -eq $displayVersion) { $displayVersion = $ntReg['ReleaseId'] }

    $build = $ntReg['CurrentBuild']
    $ubr = $ntReg['UBR']
    if ($null -ne $build -and $null -ne $ubr) {
        $buildStr = "$build.$ubr"
    }
    elseif ($null -ne $build) {
        $buildStr = $build
    }
    else {
        $buildStr = 'Unknown'
    }

    $edition = $ntReg['EditionID']
    if ($null -eq $edition) { $edition = 'Unknown' }

    $installType = $ntReg['InstallationType']
    if ($null -eq $installType) { $installType = 'Unknown' }

    return [PSCustomObject]@{
        Caption        = $caption
        Edition        = $edition
        DisplayVersion = $displayVersion
        Build          = $buildStr
        Architecture   = $arch
        InstallType    = $installType
        Hostname       = $env:COMPUTERNAME
        IsHomeEdition  = ($edition -eq 'Core')
    }
}

# ============================================================================
#  GET-MANAGEMENTAUTHORITY
# ============================================================================

function Get-ManagementAuthority {
    $result = [PSCustomObject]@{
        Authority     = 'Local'
        Details       = 'Updates managed via Settings app (no policies detected)'
        WUServer      = $null
        IsMDMManaged  = $false
        IsSCCMManaged = $false
        IsCoManaged   = $false
        IsGPOManaged  = $false
        IsWUfB        = $false
        IsWSUS        = $false
        IsSplitSource = $false
        CanModify     = $true
        MDMProvider   = $null
        AutoUpdateDisabled = $false
        Blockers      = @()
    }

    # Check SCCM/ConfigMgr
    $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
    $ccmKey = Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'
    $sccmDetected = ($null -ne $sccmService -and $ccmKey)

    # Check co-management -- is the WU workload shifted to Intune?
    $coMgmtWUShifted = $false
    if ($sccmDetected) {
        $coMgmtFlags = Get-SafeRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
        if ($null -ne $coMgmtFlags) {
            $result.IsCoManaged = $true
            # Bit 4 (value 16) = Windows Update workload shifted to Intune
            if (($coMgmtFlags -band 16) -eq 16) {
                $coMgmtWUShifted = $true
            }
        }
    }

    if ($sccmDetected) {
        if ($coMgmtWUShifted) {
            $result.Authority = 'Co-managed (WU via Intune)'
            $result.Details = 'SCCM client present, but Windows Update workload shifted to Intune'
            $result.IsSCCMManaged = $true
            $result.IsMDMManaged = $true
            $result.CanModify = $false
        }
        elseif ($result.IsCoManaged) {
            $result.Authority = 'SCCM / ConfigMgr (co-managed)'
            $result.Details = 'Co-management active, but WU workload remains with SCCM'
            $result.IsSCCMManaged = $true
            $result.CanModify = $false
        }
        else {
            $result.Authority = 'SCCM / ConfigMgr'
            $result.Details = 'Configuration Manager client detected (ccmexec service running)'
            $result.IsSCCMManaged = $true
            $result.CanModify = $false
        }
    }

    # Check MDM/Intune -- verify active enrollment before trusting PolicyManager values
    $mdmValues = Get-AllRegistryValues -Path $script:RegPath_MDM
    $mdmProvider = Test-ActiveMDMEnrollment
    if ($mdmValues.Count -gt 0) {
        if ($null -ne $mdmProvider) {
            $result.MDMProvider = $mdmProvider
            if (-not $result.IsSCCMManaged) {
                $result.Authority = 'MDM / Intune'
                $result.Details = "Active MDM enrollment detected (Provider: $mdmProvider)"
                $result.IsMDMManaged = $true
                $result.CanModify = $false
            }
        }
        else {
            # MDM policy keys exist but no active enrollment -- likely stale
            if (-not $result.IsSCCMManaged) {
                $result.Authority = 'MDM (stale?)'
                $result.Details = 'MDM policy keys found but no active enrollment detected -- may be leftover'
                $result.IsMDMManaged = $true
                $result.CanModify = $true
            }
        }
    }

    # Check WSUS
    $wuServer = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'WUServer'
    $useWU = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'UseWUServer'
    if ($null -ne $wuServer -and $useWU -eq 1) {
        if (-not $result.IsSCCMManaged -and -not $result.IsMDMManaged) {
            $result.Authority = 'WSUS'
            $result.Details = "WSUS Server: $wuServer"
            $result.IsWSUS = $true
            $result.CanModify = $false
        }
        $result.WUServer = $wuServer
    }

    # Check for WUfB indicators (GP and MDM paths)
    $wufbIndicators = @()
    $gpValues = Get-AllRegistryValues -Path $script:RegPath_WU

    # PolicyDrivenUpdateSource keys (most definitive, Windows 10 2004+)
    $srcFeature_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcFeature_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    if ($srcFeature_GP -eq 0 -or $srcFeature_MDM -eq 0) { $wufbIndicators += 'PolicyDrivenSource(Feature)' }
    if ($srcQuality_GP -eq 0 -or $srcQuality_MDM -eq 0) { $wufbIndicators += 'PolicyDrivenSource(Quality)' }

    # Deferral policies
    if ($null -ne $gpValues['DeferFeatureUpdatesPeriodInDays'] -or
        $null -ne (Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'DeferFeatureUpdatesPeriodInDays')) {
        $wufbIndicators += 'FeatureDeferral'
    }
    if ($null -ne $gpValues['DeferQualityUpdatesPeriodInDays'] -or
        $null -ne (Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'DeferQualityUpdatesPeriodInDays')) {
        $wufbIndicators += 'QualityDeferral'
    }

    # Version targeting -- requires both TargetReleaseVersion=1 AND TargetReleaseVersionInfo
    $targetVer = $gpValues['TargetReleaseVersion']
    if ($null -eq $targetVer) { $targetVer = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'TargetReleaseVersion' }
    $targetVerInfo = $gpValues['TargetReleaseVersionInfo']
    if ($null -eq $targetVerInfo) { $targetVerInfo = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'TargetReleaseVersionInfo' }
    if ($targetVer -eq 1 -and $null -ne $targetVerInfo) { $wufbIndicators += 'VersionTargeting' }

    # Compliance deadlines -- check both Configure* (MDM) and Compliance* (GP) naming conventions
    $dlFeature = $gpValues['ConfigureDeadlineForFeatureUpdates']
    if ($null -eq $dlFeature) { $dlFeature = $gpValues['ComplianceDeadlineForFU'] }
    if ($null -eq $dlFeature) { $dlFeature = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineForFeatureUpdates' }
    if ($null -ne $dlFeature) { $wufbIndicators += 'FeatureDeadline' }

    $dlQuality = $gpValues['ConfigureDeadlineForQualityUpdates']
    if ($null -eq $dlQuality) { $dlQuality = $gpValues['ComplianceDeadline'] }
    if ($null -eq $dlQuality) { $dlQuality = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineForQualityUpdates' }
    if ($null -ne $dlQuality) { $wufbIndicators += 'QualityDeadline' }

    $dlGrace = $gpValues['ConfigureDeadlineGracePeriod']
    if ($null -eq $dlGrace) { $dlGrace = $gpValues['ComplianceGracePeriod'] }
    if ($null -eq $dlGrace) { $dlGrace = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineGracePeriod' }
    if ($null -ne $dlGrace) { $wufbIndicators += 'GracePeriod' }

    $dlGraceFU = $gpValues['ConfigureDeadlineGracePeriodForFeatureUpdates']
    if ($null -eq $dlGraceFU) { $dlGraceFU = $gpValues['ComplianceGracePeriodForFU'] }
    if ($null -eq $dlGraceFU) { $dlGraceFU = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates' }
    if ($null -ne $dlGraceFU) { $wufbIndicators += 'GracePeriodFU' }

    # Channel targeting and preview builds
    if ($null -ne $gpValues['BranchReadinessLevel'] -or
        $null -ne (Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'BranchReadinessLevel')) {
        $wufbIndicators += 'BranchReadiness'
    }
    if ($null -ne $gpValues['ManagePreviewBuilds'] -or
        $null -ne (Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ManagePreviewBuilds')) {
        $wufbIndicators += 'PreviewBuilds'
    }

    # Driver exclusion
    if ($null -ne $gpValues['ExcludeWUDriversInQualityUpdate'] -or
        $null -ne (Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ExcludeWUDriversInQualityUpdate')) {
        $wufbIndicators += 'ExcludeDrivers'
    }

    $hasWSUS = ($useWU -eq 1 -and $null -ne $wuServer)
    # Check all 4 PolicyDrivenSource types for split-source detection
    $srcDriver_GP   = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcOther_GP    = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'
    $srcDriver_MDM  = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcOther_MDM   = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'
    if ($srcDriver_GP -eq 0 -or $srcDriver_MDM -eq 0) { $wufbIndicators += 'PolicyDrivenSource(Driver)' }
    if ($srcOther_GP -eq 0 -or $srcOther_MDM -eq 0)   { $wufbIndicators += 'PolicyDrivenSource(Other)' }

    $isSplitSource = ($hasWSUS -and ($srcFeature_GP -eq 0 -or $srcFeature_MDM -eq 0 -or
                                      $srcQuality_GP -eq 0 -or $srcQuality_MDM -eq 0 -or
                                      $srcDriver_GP -eq 0 -or $srcDriver_MDM -eq 0 -or
                                      $srcOther_GP -eq 0 -or $srcOther_MDM -eq 0))
    $result.IsSplitSource = $isSplitSource

    # Update blocker checks -- matches PR detect logic
    $blockers = @()

    $noAutoUpdate = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdate -eq 1) { $blockers += 'NoAutoUpdate=1' }

    $auOptionsCurrent = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'AUOptions'
    if ($auOptionsCurrent -eq 1) { $blockers += 'AUOptions=1 (Never check)' }

    $noConnect = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    if ($noConnect -eq 1) { $blockers += 'DoNotConnectToWindowsUpdateInternetLocations=1' }

    $disableUX = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetDisableUXWUAccess'
    if ($disableUX -eq 1) { $blockers += 'SetDisableUXWUAccess=1' }

    $wuSvc = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
    if ($null -ne $wuSvc -and $wuSvc.StartType -eq 'Disabled') { $blockers += 'wuauserv service Disabled' }

    $usoSvc = Get-Service -Name 'UsoSvc' -ErrorAction SilentlyContinue
    if ($null -ne $usoSvc -and $usoSvc.StartType -eq 'Disabled') { $blockers += 'UsoSvc service Disabled' }

    $result.Blockers = $blockers
    $result.AutoUpdateDisabled = ($blockers.Count -gt 0)

    # Classify: GPO with WUfB indicators, GPO without, WSUS with split-source, or Local
    if ($result.Authority -eq 'Local' -or $result.Authority -eq 'MDM (stale?)') {
        $auValues = Get-AllRegistryValues -Path $script:RegPath_AU
        if ($blockers.Count -gt 0) {
            # Blockers detected -- WUfB can't function even if indicators exist
            if (-not $result.IsSCCMManaged -and -not $result.IsMDMManaged) {
                $blockerDetail = $blockers -join '; '
                $result.Authority = "Disabled ($blockerDetail)"
                $result.Details = "Update blockers detected -- WUfB policies cannot take effect"
                $result.IsWUfB = $false
            }
        }
        elseif ($wufbIndicators.Count -gt 0 -and (-not $hasWSUS -or $isSplitSource)) {
            if ($isSplitSource) {
                $result.Authority = 'WUfB (split-source with WSUS)'
                $result.Details = "WUfB controls updates via PolicyDrivenSource; WSUS also configured at $wuServer"
            }
            else {
                $result.Authority = 'WUfB (Group Policy)'
                $result.Details = "WUfB policies detected: $($wufbIndicators -join ', ')"
            }
            $result.IsWUfB = $true
            $result.IsGPOManaged = $true
            $result.CanModify = $true
        }
        elseif ($gpValues.Count -gt 0 -or $auValues.Count -gt 0) {
            $result.Authority = 'Group Policy'
            $result.Details = 'Traditional Windows Update policies applied via Group Policy'
            $result.IsGPOManaged = $true
            $result.CanModify = $true
        }
    }
    elseif ($hasWSUS -and $isSplitSource -and -not $result.IsSCCMManaged) {
        # WSUS was set as authority above, but PolicyDrivenSource overrides for some update types
        $result.Authority = 'WUfB (split-source with WSUS)'
        $result.Details = "WUfB controls updates via PolicyDrivenSource; WSUS also configured at $wuServer"
        $result.IsWUfB = $true
        $result.IsWSUS = $true
    }

    return $result
}

# ============================================================================
#  GET-UPDATEPOLICIES
# ============================================================================

function Get-UpdatePolicies {
    # --- OS Version Pinning ---
    $targetEnabled = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'TargetReleaseVersion'
    $targetVersion = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'TargetReleaseVersionInfo'
    $productVersion = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ProductVersion'

    # --- Update Source ---
    $wuServer = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'WUServer'
    $wuStatusServer = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'WUStatusServer'
    $useWUServer = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'UseWUServer'
    $noInternet = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'DoNotConnectToWindowsUpdateInternetLocations'
    $disableUXAccess = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetDisableUXWUAccess'

    # --- Policy-Driven Update Source (Windows 10 2004+ / Windows 11) ---
    $srcFeature_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcDriver_GP   = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcOther_GP    = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'
    $srcFeature_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForFeatureUpdates'
    $srcQuality_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForQualityUpdates'
    $srcDriver_MDM  = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForDriverUpdates'
    $srcOther_MDM   = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'SetPolicyDrivenUpdateSourceForOtherUpdates'

    # Resolve: GP wins, then MDM
    if ($null -ne $srcFeature_GP) { $srcFeature = $srcFeature_GP } elseif ($null -ne $srcFeature_MDM) { $srcFeature = $srcFeature_MDM } else { $srcFeature = $null }
    if ($null -ne $srcQuality_GP) { $srcQuality = $srcQuality_GP } elseif ($null -ne $srcQuality_MDM) { $srcQuality = $srcQuality_MDM } else { $srcQuality = $null }
    if ($null -ne $srcDriver_GP)  { $srcDriver  = $srcDriver_GP }  elseif ($null -ne $srcDriver_MDM)  { $srcDriver  = $srcDriver_MDM }  else { $srcDriver  = $null }
    if ($null -ne $srcOther_GP)   { $srcOther   = $srcOther_GP }   elseif ($null -ne $srcOther_MDM)   { $srcOther   = $srcOther_MDM }   else { $srcOther   = $null }

    # --- Compliance Deadlines ---
    # GP writes native names (ComplianceDeadlineForFU, ComplianceDeadline); MDM/CSP uses Configure* names
    # ADMX-backed CSP also writes to GP path with native names. Check both at GP path.
    $deadlineFeature_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ConfigureDeadlineForFeatureUpdates'
    if ($null -eq $deadlineFeature_GP) {
        $deadlineFeature_GP = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ComplianceDeadlineForFU'
    }
    $deadlineQuality_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ConfigureDeadlineForQualityUpdates'
    if ($null -eq $deadlineQuality_GP) {
        $deadlineQuality_GP = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ComplianceDeadline'
    }
    $deadlineGrace_GP    = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ConfigureDeadlineGracePeriod'
    if ($null -eq $deadlineGrace_GP) {
        $deadlineGrace_GP = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ComplianceGracePeriod'
    }
    $deadlineGraceFU_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates'
    if ($null -eq $deadlineGraceFU_GP) {
        $deadlineGraceFU_GP = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ComplianceGracePeriodForFU'
    }
    $deadlineFeature_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineForFeatureUpdates'
    $deadlineQuality_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineForQualityUpdates'
    $deadlineGrace_MDM   = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineGracePeriod'
    $deadlineGraceFU_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ConfigureDeadlineGracePeriodForFeatureUpdates'

    if ($null -ne $deadlineFeature_GP) { $deadlineFeature = $deadlineFeature_GP } else { $deadlineFeature = $deadlineFeature_MDM }
    if ($null -ne $deadlineQuality_GP) { $deadlineQuality = $deadlineQuality_GP } else { $deadlineQuality = $deadlineQuality_MDM }
    if ($null -ne $deadlineGrace_GP)   { $deadlineGrace   = $deadlineGrace_GP }   else { $deadlineGrace   = $deadlineGrace_MDM }
    if ($null -ne $deadlineGraceFU_GP) { $deadlineGraceFU = $deadlineGraceFU_GP } else { $deadlineGraceFU = $deadlineGraceFU_MDM }

    # --- Channel / Preview Builds ---
    $branchLevel_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'BranchReadinessLevel'
    $branchLevel_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'BranchReadinessLevel'
    if ($null -ne $branchLevel_GP) { $branchLevel = $branchLevel_GP } else { $branchLevel = $branchLevel_MDM }

    $previewBuilds_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ManagePreviewBuilds'
    $previewBuilds_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ManagePreviewBuilds'
    if ($null -ne $previewBuilds_GP) { $previewBuilds = $previewBuilds_GP } else { $previewBuilds = $previewBuilds_MDM }

    # --- Driver Exclusion ---
    $excludeDrivers_GP  = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'ExcludeWUDriversInQualityUpdate'
    $excludeDrivers_MDM = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'ExcludeWUDriversInQualityUpdate'
    if ($null -ne $excludeDrivers_GP) { $excludeDrivers = $excludeDrivers_GP } else { $excludeDrivers = $excludeDrivers_MDM }

    # --- Deferrals (multi-source with priority) ---
    $gpFeatureDefer = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'DeferFeatureUpdatesPeriodInDays'
    $mdmFeatureDefer = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'DeferFeatureUpdatesPeriodInDays'
    $uxFeatureDefer = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'FlightSettingsMaxPauseDays'

    if ($null -ne $gpFeatureDefer)       { $featureDefer = $gpFeatureDefer;  $featureSource = 'Group Policy' }
    elseif ($null -ne $mdmFeatureDefer)  { $featureDefer = $mdmFeatureDefer; $featureSource = 'MDM' }
    elseif ($null -ne $uxFeatureDefer)   { $featureDefer = $uxFeatureDefer;  $featureSource = 'Local' }
    else                                 { $featureDefer = $null;            $featureSource = $null }

    $gpQualityDefer = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'DeferQualityUpdatesPeriodInDays'
    $mdmQualityDefer = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name 'DeferQualityUpdatesPeriodInDays'

    if ($null -ne $gpQualityDefer)       { $qualityDefer = $gpQualityDefer;  $qualitySource = 'Group Policy' }
    elseif ($null -ne $mdmQualityDefer)  { $qualityDefer = $mdmQualityDefer; $qualitySource = 'MDM' }
    else                                 { $qualityDefer = $null;            $qualitySource = $null }

    # --- Auto Update Behavior ---
    $noAutoUpdate = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'NoAutoUpdate'
    $auOptions = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'AUOptions'
    $installDay = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'ScheduledInstallDay'
    $installTime = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'ScheduledInstallTime'
    $alwaysReboot = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'AlwaysAutoRebootAtScheduledTime'

    # --- Pause State (check multiple locations) ---
    $pauseFeatureStart = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesStartTime'
    $pauseFeatureEnd   = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesEndTime'
    $pauseQualityStart = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'PauseQualityUpdatesStartTime'
    $pauseQualityEnd   = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'PauseQualityUpdatesEndTime'

    # Also check UX Settings path for user-initiated pauses
    if ($null -eq $pauseFeatureStart) {
        $pauseFeatureStart = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'PauseFeatureUpdatesStartTime'
    }
    if ($null -eq $pauseFeatureEnd) {
        $pauseFeatureEnd = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'PauseFeatureUpdatesEndTime'
    }
    if ($null -eq $pauseQualityStart) {
        $pauseQualityStart = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'PauseQualityUpdatesStartTime'
    }
    if ($null -eq $pauseQualityEnd) {
        $pauseQualityEnd = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'PauseQualityUpdatesEndTime'
    }

    # Also check the UpdatePolicy\Settings path
    $pauseFeatureDate = Get-SafeRegistryValue -Path $script:RegPath_Pause -Name 'PausedFeatureDate'
    $pauseQualityDate = Get-SafeRegistryValue -Path $script:RegPath_Pause -Name 'PausedQualityDate'
    $pauseFeatureStatus = Get-SafeRegistryValue -Path $script:RegPath_Pause -Name 'PausedFeatureStatus'
    $pauseQualityStatus = Get-SafeRegistryValue -Path $script:RegPath_Pause -Name 'PausedQualityStatus'

    # Consolidated pause expiry from Settings app
    $pauseExpiryTime = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'PauseUpdatesExpiryTime'

    # --- Active Hours ---
    # Policy-enforced (AU path)
    $setActiveHoursGP = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'SetActiveHours'
    $activeStartGP    = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'ActiveHoursStart'
    $activeEndGP      = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'ActiveHoursEnd'

    # User-set (UX path)
    $activeStartUX = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'ActiveHoursStart'
    $activeEndUX   = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'ActiveHoursEnd'

    if ($null -ne $setActiveHoursGP -and $setActiveHoursGP -eq 1) {
        $activeStart = $activeStartGP; $activeEnd = $activeEndGP; $activeSource = 'Group Policy'
    }
    elseif ($null -ne $activeStartUX) {
        $activeStart = $activeStartUX; $activeEnd = $activeEndUX; $activeSource = 'Local'
    }
    else {
        $activeStart = $null; $activeEnd = $null; $activeSource = $null
    }

    # Smart active hours (Windows auto-adjusts)
    $smartActiveHours = Get-SafeRegistryValue -Path $script:RegPath_UX -Name 'SmartActiveHoursState'

    # --- Delivery Optimization ---
    $doGP  = Get-SafeRegistryValue -Path $script:RegPath_DO_Policy -Name 'DownloadMode'
    $doMDM = Get-SafeRegistryValue -Path $script:RegPath_DO_MDM -Name 'DODownloadMode'
    if ($null -ne $doGP)       { $doMode = $doGP;  $doSource = 'Group Policy' }
    elseif ($null -ne $doMDM)  { $doMode = $doMDM; $doSource = 'MDM' }
    else                       { $doMode = $null;   $doSource = 'Default (OS-managed)' }

    # --- Dual-Scan Detection ---
    # Dual-scan: WSUS active + WUfB deferrals, but NO PolicyDrivenSource override
    # If PolicyDrivenSource is set, it's a valid split-source config, not a dual-scan problem
    # DisableDualScan=1 suppresses dual-scan (legacy, deprecated on Win 11, but still functional on Win 10)
    $hasPolicyDrivenSource = ($null -ne $srcFeature -or $null -ne $srcQuality)
    $disableDualScan = Get-SafeRegistryValue -Path $script:RegPath_WU -Name 'DisableDualScan'
    $dualScan = $false
    if ($useWUServer -eq 1 -and ($null -ne $gpFeatureDefer -or $null -ne $gpQualityDefer) -and -not $hasPolicyDrivenSource -and $disableDualScan -ne 1) {
        $dualScan = $true
    }

    return [PSCustomObject]@{
        # OS Pinning
        TargetReleaseVersion     = $targetEnabled
        TargetReleaseVersionInfo = $targetVersion
        ProductVersion           = $productVersion
        # Update Source
        WUServer                 = $wuServer
        WUStatusServer           = $wuStatusServer
        UseWUServer              = $useWUServer
        BlockInternetWU          = $noInternet
        DisableUXWUAccess        = $disableUXAccess
        DualScanDetected         = $dualScan
        # Policy-Driven Update Source
        SourceFeatureUpdates     = $srcFeature
        SourceQualityUpdates     = $srcQuality
        SourceDriverUpdates      = $srcDriver
        SourceOtherUpdates       = $srcOther
        # Deferrals
        FeatureDeferralDays      = $featureDefer
        FeatureDeferralSource    = $featureSource
        QualityDeferralDays      = $qualityDefer
        QualityDeferralSource    = $qualitySource
        # Compliance Deadlines
        DeadlineFeatureDays      = $deadlineFeature
        DeadlineQualityDays      = $deadlineQuality
        DeadlineGracePeriod      = $deadlineGrace
        DeadlineGracePeriodFU    = $deadlineGraceFU
        # Channel / Preview
        BranchReadinessLevel     = $branchLevel
        ManagePreviewBuilds      = $previewBuilds
        # Driver Exclusion
        ExcludeDrivers           = $excludeDrivers
        # Auto Update
        NoAutoUpdate             = $noAutoUpdate
        AUOptions                = $auOptions
        ScheduledInstallDay      = $installDay
        ScheduledInstallTime     = $installTime
        AlwaysAutoReboot         = $alwaysReboot
        # Pause
        PauseFeatureStart        = $pauseFeatureStart
        PauseFeatureEnd          = $pauseFeatureEnd
        PauseQualityStart        = $pauseQualityStart
        PauseQualityEnd          = $pauseQualityEnd
        PauseFeatureDate         = $pauseFeatureDate
        PauseQualityDate         = $pauseQualityDate
        PauseFeatureStatus       = $pauseFeatureStatus
        PauseQualityStatus       = $pauseQualityStatus
        PauseExpiryTime          = $pauseExpiryTime
        # Active Hours
        ActiveHoursStart         = $activeStart
        ActiveHoursEnd           = $activeEnd
        ActiveHoursSource        = $activeSource
        SmartActiveHours         = $smartActiveHours
        # Delivery Optimization
        DODownloadMode           = $doMode
        DOSource                 = $doSource
    }
}

# ============================================================================
#  DISPLAY HELPERS
# ============================================================================

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "  --- $Title ---" -ForegroundColor Cyan
}

function Write-ReportLine {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Color = 'White',
        [string]$Suffix = ''
    )
    $pad = 28 - $Label.Length
    if ($pad -lt 1) { $pad = 1 }
    Write-Host ("  " + $Label + (' ' * $pad) + ": ") -NoNewline -ForegroundColor Gray
    Write-Host $Value -NoNewline -ForegroundColor $Color
    if ($Suffix) {
        Write-Host "  $Suffix" -ForegroundColor DarkGray
    }
    else {
        Write-Host ""
    }
}

function Format-PauseDate {
    param($DateValue)
    if ($null -eq $DateValue -or $DateValue -eq '') { return $null }
    try {
        $dt = [DateTime]::Parse($DateValue)
        return $dt.ToString('yyyy-MM-dd HH:mm')
    }
    catch { }
    try {
        # Try as FILETIME
        $dt = [DateTime]::FromFileTimeUtc([long]$DateValue)
        return $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm')
    }
    catch { }
    return $DateValue.ToString()
}

function Format-Hour {
    param([int]$Hour)
    if ($Hour -eq 0) { return '12:00 AM' }
    elseif ($Hour -lt 12) { return "$($Hour):00 AM" }
    elseif ($Hour -eq 12) { return '12:00 PM' }
    else { return "$($Hour - 12):00 PM" }
}

# ============================================================================
#  SHOW-UPDATEREPORT
# ============================================================================

function Show-UpdateReport {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$OSInfo,
        [Parameter(Mandatory)]
        [PSCustomObject]$Authority,
        [Parameter(Mandatory)]
        [PSCustomObject]$Policies,
        [Parameter(Mandatory)]
        [PSCustomObject]$ServiceState,
        [Parameter(Mandatory)]
        [PSCustomObject]$UpdateStatus,
        [array]$UpdateHistory = @(),
        [array]$UpdateServices = @()
    )

    $divider = "  " + ("=" * 72)
    $now = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    Write-Host ""
    Write-Host $divider -ForegroundColor DarkCyan
    Write-Host "    WUDUP - Windows Update Dashboard: Unified Provisioning" -ForegroundColor White
    Write-Host "    Generated: $now" -ForegroundColor DarkGray
    Write-Host $divider -ForegroundColor DarkCyan

    # --- OS Information ---
    Write-Section "OS Information"
    Write-ReportLine "Computer Name" $OSInfo.Hostname 'White'
    Write-ReportLine "OS" $OSInfo.Caption 'White'
    $verStr = "$($OSInfo.DisplayVersion)  (Build $($OSInfo.Build))"
    Write-ReportLine "Version" $verStr 'White'
    Write-ReportLine "Architecture" $OSInfo.Architecture 'White'
    Write-ReportLine "Edition" $OSInfo.Edition 'White'

    if ($OSInfo.IsHomeEdition) {
        Write-Host ""
        Write-Host "    NOTE: Home edition - some Group Policy settings may not be honored." -ForegroundColor Yellow
    }

    # --- Management Authority ---
    Write-Section "Management Authority"
    $authColor = 'Green'
    if ($Authority.IsMDMManaged) { $authColor = 'Yellow' }
    elseif ($Authority.IsSCCMManaged) { $authColor = 'Yellow' }
    elseif ($Authority.IsWSUS) { $authColor = 'Yellow' }

    Write-ReportLine "Managed By" $Authority.Authority $authColor
    Write-ReportLine "Details" $Authority.Details 'DarkGray'

    if ($Authority.IsCoManaged) {
        if ($Authority.Authority -like '*via Intune*') { $coMgmtLabel = 'WU workload shifted to Intune' } else { $coMgmtLabel = 'WU workload remains with SCCM' }
        Write-ReportLine "Co-Management" $coMgmtLabel 'Cyan'
    }

    if ($null -ne $Authority.MDMProvider) {
        Write-ReportLine "MDM Provider" $Authority.MDMProvider 'White'
    }

    if (-not $Authority.CanModify) {
        Write-Host ""
        Write-Host "    WARNING: Local registry changes may be overwritten by $($Authority.Authority)." -ForegroundColor Red
    }

    # --- Windows Update Service ---
    Write-Section "Windows Update Service"
    $svcColor = 'Green'
    if ($ServiceState.Status -eq 'Stopped') { $svcColor = 'Yellow' }
    if ($ServiceState.StartType -eq 'Disabled') { $svcColor = 'Red' }
    Write-ReportLine "WU Agent (wuauserv)" "$($ServiceState.Status) / $($ServiceState.StartType)" $svcColor
    $usoColor = 'Green'
    if ($ServiceState.UsoStatus -eq 'Stopped') { $usoColor = 'Yellow' }
    if ($ServiceState.UsoStartType -eq 'Disabled') { $usoColor = 'Red' }
    Write-ReportLine "Update Orchestrator (UsoSvc)" "$($ServiceState.UsoStatus) / $($ServiceState.UsoStartType)" $usoColor
    if ($ServiceState.StartType -eq 'Disabled') {
        Write-Host ""
        Write-Host "    WARNING: Windows Update service is disabled - no updates will be processed." -ForegroundColor Red
    }
    if ($ServiceState.UsoStartType -eq 'Disabled') {
        Write-Host ""
        Write-Host "    WARNING: Update Orchestrator is disabled - updates cannot be initiated." -ForegroundColor Red
    }

    # --- Update Status ---
    Write-Section "Update Status"
    if ($UpdateStatus.RebootRequired) {
        # COM API says reboot needed -- authoritative, matches Settings app
        $sources = @()
        if ($UpdateStatus.RebootRequiredWUReg) { $sources += 'WU registry' }
        if ($UpdateStatus.RebootRequiredCBS)   { $sources += 'CBS' }
        if ($sources.Count -gt 0) { $detail = " (flags: $($sources -join ', '))" } else { $detail = '' }
        Write-ReportLine "Pending Reboot" "YES$detail" 'Red'
    }
    elseif ($UpdateStatus.RebootRequiredWUReg -or $UpdateStatus.RebootRequiredCBS) {
        # Registry flags present but COM API says no reboot needed -- stale flags
        $sources = @()
        if ($UpdateStatus.RebootRequiredWUReg) { $sources += 'WU registry' }
        if ($UpdateStatus.RebootRequiredCBS)   { $sources += 'CBS' }
        Write-ReportLine "Pending Reboot" "No (stale $($sources -join ', ') flag present)" 'Yellow'
    }
    else {
        Write-ReportLine "Pending Reboot" "No" 'Green'
    }

    if ($null -ne $UpdateStatus.LastInstallTime -and $UpdateStatus.LastInstallTime -ne '') {
        Write-ReportLine "Last Install" $UpdateStatus.LastInstallTime 'White'
    }
    else {
        Write-ReportLine "Last Install" "(unknown)" 'DarkGray'
    }

    if ($null -ne $UpdateStatus.LastDetectTime -and $UpdateStatus.LastDetectTime -ne '') {
        Write-ReportLine "Last Scan" $UpdateStatus.LastDetectTime 'White'
    }
    else {
        Write-ReportLine "Last Scan" "(unknown)" 'DarkGray'
    }

    # --- OS Version Pinning ---
    Write-Section "OS Version Pinning"
    if ($Policies.TargetReleaseVersion -eq 1) {
        Write-ReportLine "Version Pinning" "ENABLED" 'Green'
        $tvInfo = $Policies.TargetReleaseVersionInfo
        if ($null -eq $tvInfo) { $tvInfo = '(not set)' }
        Write-ReportLine "Target Version" $tvInfo 'Green'
        $pv = $Policies.ProductVersion
        if ($null -eq $pv) { $pv = '(not set)' }
        Write-ReportLine "Product" $pv 'Green'
    }
    else {
        Write-ReportLine "Version Pinning" "Not configured" 'DarkGray'
        Write-ReportLine "Target Version" "(not set)" 'DarkGray'
        Write-ReportLine "Product" "(not set)" 'DarkGray'
    }

    # --- Update Source ---
    Write-Section "Update Source"
    if ($null -ne $Policies.WUServer) {
        Write-ReportLine "WSUS Server" $Policies.WUServer 'Yellow'
        $status = $Policies.WUStatusServer
        if ($null -eq $status) { $status = '(not configured)' }
        Write-ReportLine "WSUS Status Server" $status 'Yellow'
    }
    else {
        Write-ReportLine "WSUS Server" "(not configured - using Microsoft Update)" 'DarkGray'
    }

    if ($Policies.UseWUServer -eq 1) {
        Write-ReportLine "Use WSUS" "Yes" 'Yellow'
    }
    elseif ($null -ne $Policies.UseWUServer) {
        Write-ReportLine "Use WSUS" "No" 'Green'
    }
    else {
        Write-ReportLine "Use WSUS" "(not configured)" 'DarkGray'
    }

    if ($Policies.BlockInternetWU -eq 1) {
        Write-ReportLine "Block Internet WU" "Yes - Internet sources blocked" 'Red'
    }
    else {
        Write-ReportLine "Block Internet WU" "No" 'Green'
    }

    if ($Policies.DualScanDetected) {
        Write-Host ""
        Write-ReportLine "Dual Scan" "DETECTED - WSUS + WUfB deferrals, no PolicyDrivenSource" 'Red'
        Write-Host "    WARNING: Dual scan can cause unexpected update behavior. Feature/quality" -ForegroundColor Yellow
        Write-Host "    updates may bypass WSUS and come directly from Microsoft Update." -ForegroundColor Yellow
        Write-Host "    Consider setting SetPolicyDrivenUpdateSourceFor* to resolve." -ForegroundColor Yellow
    }

    # --- Policy-Driven Update Source ---
    $srcNames = @(
        @{ Label = 'Feature Updates';  Value = $Policies.SourceFeatureUpdates }
        @{ Label = 'Quality Updates';  Value = $Policies.SourceQualityUpdates }
        @{ Label = 'Driver Updates';   Value = $Policies.SourceDriverUpdates }
        @{ Label = 'Other Updates';    Value = $Policies.SourceOtherUpdates }
    )
    $anySrcSet = ($srcNames | Where-Object { $null -ne $_.Value }).Count -gt 0
    if ($anySrcSet) {
        Write-Section "Policy-Driven Update Source"
        foreach ($src in $srcNames) {
            if ($null -ne $src.Value) {
                if ($src.Value -eq 0) { $srcLabel = 'Windows Update (WUfB)' } elseif ($src.Value -eq 1) { $srcLabel = 'WSUS' } else { $srcLabel = "Unknown ($($src.Value))" }
                if ($src.Value -eq 0) { $srcColor = 'Green' } else { $srcColor = 'Yellow' }
                Write-ReportLine "  $($src.Label)" $srcLabel $srcColor
            }
            else {
                Write-ReportLine "  $($src.Label)" "(not configured)" 'DarkGray'
            }
        }
    }

    # --- Deferral Policies ---
    Write-Section "Deferral Policies"
    if ($null -ne $Policies.FeatureDeferralDays) {
        $fColor = 'Green'
        if ($Policies.FeatureDeferralDays -eq 0) { $fColor = 'Yellow' }
        Write-ReportLine "Feature Update Deferral" "$($Policies.FeatureDeferralDays) days" $fColor "[Source: $($Policies.FeatureDeferralSource)]"
    }
    else {
        Write-ReportLine "Feature Update Deferral" "Not configured (0 days)" 'DarkGray'
    }

    if ($null -ne $Policies.QualityDeferralDays) {
        $qColor = 'Green'
        if ($Policies.QualityDeferralDays -eq 0) { $qColor = 'Yellow' }
        Write-ReportLine "Quality Update Deferral" "$($Policies.QualityDeferralDays) days" $qColor "[Source: $($Policies.QualityDeferralSource)]"
    }
    else {
        Write-ReportLine "Quality Update Deferral" "Not configured (0 days)" 'DarkGray'
    }

    # --- Compliance Deadlines ---
    $anyDeadline = ($null -ne $Policies.DeadlineFeatureDays -or $null -ne $Policies.DeadlineQualityDays)
    if ($anyDeadline) {
        Write-Section "Compliance Deadlines"
        if ($null -ne $Policies.DeadlineFeatureDays) {
            Write-ReportLine "Feature Deadline" "$($Policies.DeadlineFeatureDays) days" 'White'
        }
        else {
            Write-ReportLine "Feature Deadline" "(not configured)" 'DarkGray'
        }
        if ($null -ne $Policies.DeadlineQualityDays) {
            Write-ReportLine "Quality Deadline" "$($Policies.DeadlineQualityDays) days" 'White'
        }
        else {
            Write-ReportLine "Quality Deadline" "(not configured)" 'DarkGray'
        }
        if ($null -ne $Policies.DeadlineGracePeriod) {
            Write-ReportLine "Grace Period" "$($Policies.DeadlineGracePeriod) days" 'White'
        }
        if ($null -ne $Policies.DeadlineGracePeriodFU) {
            Write-ReportLine "Grace Period (Feature)" "$($Policies.DeadlineGracePeriodFU) days" 'White'
        }
    }

    # --- Channel / Preview Builds ---
    $anyChannel = ($null -ne $Policies.BranchReadinessLevel -or $null -ne $Policies.ManagePreviewBuilds)
    if ($anyChannel) {
        Write-Section "Channel / Preview Builds"
        if ($null -ne $Policies.BranchReadinessLevel) {
            $branchDesc = switch ([int]$Policies.BranchReadinessLevel) {
                2   { 'Windows Insider - Fast' }
                4   { 'Windows Insider - Slow' }
                8   { 'Release Preview' }
                16  { 'Semi-Annual Channel' }
                32  { 'General Availability Channel' }
                64  { 'Release Preview (Quality Updates Only)' }
                128 { 'Canary Channel' }
                default { "Unknown ($($Policies.BranchReadinessLevel))" }
            }
            Write-ReportLine "Channel" $branchDesc 'White'
        }
        if ($null -ne $Policies.ManagePreviewBuilds) {
            $previewDesc = switch ([int]$Policies.ManagePreviewBuilds) {
                0 { 'Disabled (no preview builds)' }
                1 { 'Disabled once next release is public' }
                2 { 'Enabled (preview builds allowed)' }
                3 { 'User selection (default)' }
                default { "Unknown ($($Policies.ManagePreviewBuilds))" }
            }
            Write-ReportLine "Preview Builds" $previewDesc 'White'
        }
    }

    # --- Driver Exclusion ---
    if ($null -ne $Policies.ExcludeDrivers) {
        if ($Policies.ExcludeDrivers -eq 1) {
            Write-ReportLine "Driver Updates" "Excluded from Windows Update" 'Yellow'
        }
        else {
            Write-ReportLine "Driver Updates" "Included in Windows Update" 'Green'
        }
    }

    # --- Auto-Update Behavior ---
    Write-Section "Auto-Update Behavior"
    if ($Policies.NoAutoUpdate -eq 1) {
        Write-ReportLine "Auto Updates" "DISABLED" 'Red'
    }
    elseif ($null -ne $Policies.NoAutoUpdate) {
        Write-ReportLine "Auto Updates" "Enabled" 'Green'
    }
    else {
        Write-ReportLine "Auto Updates" "Enabled (default)" 'Green'
    }

    if ($null -ne $Policies.AUOptions) {
        $auDesc = $script:AUOptionsMap[[int]$Policies.AUOptions]
        if ($null -eq $auDesc) { $auDesc = "Unknown ($($Policies.AUOptions))" }
        $auColor = 'Green'
        if ($Policies.AUOptions -le 2) { $auColor = 'Yellow' }
        Write-ReportLine "AU Option" "$($Policies.AUOptions) - $auDesc" $auColor
    }
    else {
        Write-ReportLine "AU Option" "(not configured - OS default)" 'DarkGray'
    }

    if ($null -ne $Policies.ScheduledInstallDay) {
        $dayName = $script:InstallDayMap[[int]$Policies.ScheduledInstallDay]
        if ($null -eq $dayName) { $dayName = $Policies.ScheduledInstallDay }
        Write-ReportLine "Scheduled Install Day" $dayName 'White'
    }
    else {
        Write-ReportLine "Scheduled Install Day" "(not set)" 'DarkGray'
    }

    if ($null -ne $Policies.ScheduledInstallTime) {
        Write-ReportLine "Scheduled Install Time" (Format-Hour $Policies.ScheduledInstallTime) 'White'
    }
    else {
        Write-ReportLine "Scheduled Install Time" "(not set)" 'DarkGray'
    }

    if ($Policies.AlwaysAutoReboot -eq 1) {
        Write-ReportLine "Always Auto Reboot" "Yes" 'Yellow'
    }
    else {
        Write-ReportLine "Always Auto Reboot" "No" 'Green'
    }

    if ($Policies.DisableUXWUAccess -eq 1) {
        Write-ReportLine "Update UI Access" "BLOCKED - Settings > Update hidden from users" 'Red'
    }
    else {
        Write-ReportLine "Update UI Access" "Visible (default)" 'Green'
    }

    # --- Pause Status ---
    Write-Section "Pause Status"
    $featurePaused = $false
    $qualityPaused = $false

    # Check if currently paused by examining end dates
    $featureEndParsed = $false
    $featureDateUnparseable = $false
    if ($null -ne $Policies.PauseFeatureEnd) {
        try {
            $endDt = [DateTime]::Parse($Policies.PauseFeatureEnd)
            $featureEndParsed = $true
            if ($endDt -gt (Get-Date)) { $featurePaused = $true }
        }
        catch {
            # Could not parse date -- do not assume paused
            $featureDateUnparseable = $true
        }
    }
    # Only fall back to status flag when no end date was available to parse
    if (-not $featureEndParsed -and -not $featureDateUnparseable) {
        if ($null -ne $Policies.PauseFeatureStatus -and $Policies.PauseFeatureStatus -eq 1) {
            $featurePaused = $true
        }
    }

    $qualityEndParsed = $false
    $qualityDateUnparseable = $false
    if ($null -ne $Policies.PauseQualityEnd) {
        try {
            $endDt = [DateTime]::Parse($Policies.PauseQualityEnd)
            $qualityEndParsed = $true
            if ($endDt -gt (Get-Date)) { $qualityPaused = $true }
        }
        catch {
            $qualityDateUnparseable = $true
        }
    }
    if (-not $qualityEndParsed -and -not $qualityDateUnparseable) {
        if ($null -ne $Policies.PauseQualityStatus -and $Policies.PauseQualityStatus -eq 1) {
            $qualityPaused = $true
        }
    }

    if ($featurePaused) {
        $startStr = Format-PauseDate $Policies.PauseFeatureStart
        $endStr = Format-PauseDate $Policies.PauseFeatureEnd
        Write-ReportLine "Feature Updates" "PAUSED" 'Red'
        if ($startStr) { Write-ReportLine "  Paused Since" $startStr 'Red' }
        if ($endStr) { Write-ReportLine "  Resumes" $endStr 'Yellow' }
    }
    elseif ($featureDateUnparseable) {
        Write-ReportLine "Feature Updates" "Unknown (date unreadable)" 'Yellow'
        Write-ReportLine "  Raw Value" "$($Policies.PauseFeatureEnd)" 'Yellow' "(could not parse date)"
    }
    else {
        Write-ReportLine "Feature Updates" "Not paused" 'Green'
    }

    if ($qualityPaused) {
        $startStr = Format-PauseDate $Policies.PauseQualityStart
        $endStr = Format-PauseDate $Policies.PauseQualityEnd
        Write-ReportLine "Quality Updates" "PAUSED" 'Red'
        if ($startStr) { Write-ReportLine "  Paused Since" $startStr 'Red' }
        if ($endStr) { Write-ReportLine "  Resumes" $endStr 'Yellow' }
    }
    elseif ($qualityDateUnparseable) {
        Write-ReportLine "Quality Updates" "Unknown (date unreadable)" 'Yellow'
        Write-ReportLine "  Raw Value" "$($Policies.PauseQualityEnd)" 'Yellow' "(could not parse date)"
    }
    else {
        Write-ReportLine "Quality Updates" "Not paused" 'Green'
    }
    if ($null -ne $Policies.PauseExpiryTime -and $Policies.PauseExpiryTime -ne '') {
        Write-ReportLine "Pause Expiry" $Policies.PauseExpiryTime 'Yellow'
    }

    # --- Active Hours ---
    Write-Section "Active Hours"
    if ($null -ne $Policies.ActiveHoursStart -and $null -ne $Policies.ActiveHoursEnd) {
        $startH = Format-Hour $Policies.ActiveHoursStart
        $endH = Format-Hour $Policies.ActiveHoursEnd
        Write-ReportLine "Active Hours" "$startH - $endH" 'Green' "[Source: $($Policies.ActiveHoursSource)]"
    }
    else {
        Write-ReportLine "Active Hours" "(not configured)" 'DarkGray'
    }

    if ($Policies.SmartActiveHours -eq 1) {
        Write-ReportLine "Smart Active Hours" "Enabled (auto-adjusted)" 'Green'
    }
    elseif ($null -ne $Policies.SmartActiveHours -and $Policies.SmartActiveHours -eq 0) {
        Write-ReportLine "Smart Active Hours" "Disabled" 'DarkGray'
    }
    else {
        Write-ReportLine "Smart Active Hours" "(OS default)" 'DarkGray'
    }

    # --- Delivery Optimization ---
    Write-Section "Delivery Optimization"
    if ($null -ne $Policies.DODownloadMode) {
        $doDesc = $script:DODownloadModeMap[[int]$Policies.DODownloadMode]
        if ($null -eq $doDesc) { $doDesc = "Unknown ($($Policies.DODownloadMode))" }
        Write-ReportLine "Download Mode" "$($Policies.DODownloadMode) - $doDesc" 'White' "[Source: $($Policies.DOSource)]"
    }
    else {
        Write-ReportLine "Download Mode" "Default (OS-managed)" 'DarkGray'
    }

    # --- Recent Update History ---
    if ($UpdateHistory.Count -gt 0) {
        Write-Section "Recent Update History"
        foreach ($entry in $UpdateHistory) {
            if ($entry.Date) { $dateStr = $entry.Date.ToString('yyyy-MM-dd HH:mm') } else { $dateStr = '(unknown)' }
            $resultColor = switch ($entry.Result) {
                'Succeeded' { 'Green' }
                'Failed' { 'Red' }
                'Aborted' { 'Red' }
                'In Progress' { 'Yellow' }
                default { 'White' }
            }
            $label = "$dateStr  $($entry.Operation)"
            Write-ReportLine $label $entry.Title $resultColor
            # Show result on a separate line if not succeeded
            if ($entry.Result -ne 'Succeeded') {
                Write-ReportLine "  Result" $entry.Result $resultColor
            }
        }
    }

    # --- Registered Update Services (Runtime) ---
    if ($UpdateServices.Count -gt 0) {
        Write-Section "Registered Update Services (Runtime)"
        foreach ($svc in $UpdateServices) {
            if ($svc.IsDefaultAUService) { $svcColor = 'Green' } else { $svcColor = 'DarkGray' }
            $label = $svc.Name
            if ($svc.IsDefaultAUService) { $label += ' [DEFAULT]' }
            if ($svc.ServiceUrl) { $detail = $svc.ServiceUrl } else { $detail = '(no URL - built-in)' }
            Write-ReportLine "  $label" $detail $svcColor
        }
    }

    Write-Host ""
    Write-Host $divider -ForegroundColor DarkCyan
}

# ============================================================================
#  MODIFICATION FUNCTIONS
# ============================================================================

function Set-OSPin {
    Write-Host ""
    Write-Host "  --- Set OS Version Pin ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This pins the device to a specific Windows feature update version." -ForegroundColor Gray
    Write-Host "  The device will not be offered feature updates beyond this version." -ForegroundColor Gray
    Write-Host ""

    # Detect current OS for default product
    $currentOS = Get-OSInfo
    $defaultProduct = 'Windows 10'
    if ($currentOS.Caption -like '*Windows 11*') { $defaultProduct = 'Windows 11' }

    Write-Host "  Current OS: $($currentOS.Caption) $($currentOS.DisplayVersion)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Product options:  1) Windows 10   2) Windows 11" -ForegroundColor White
    $prodChoice = Read-Host "  Select product [default: $defaultProduct]"
    if ($prodChoice -eq '1') { $productVersion = 'Windows 10' }
    elseif ($prodChoice -eq '2') { $productVersion = 'Windows 11' }
    elseif ($prodChoice -eq '') { $productVersion = $defaultProduct }
    else { $productVersion = $defaultProduct }

    Write-Host ""
    Write-Host "  Common versions:  21H2, 22H2, 23H2, 24H2" -ForegroundColor White
    $versionInfo = Read-Host "  Enter target version (e.g., 24H2)"
    if ([string]::IsNullOrWhiteSpace($versionInfo)) {
        Write-Host "  Cancelled - no version entered." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  Setting: $productVersion pinned to $versionInfo" -ForegroundColor White
    $confirm = Read-Host "  Confirm? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    try {
        Ensure-RegistryPath -Path $script:RegPath_WU
        New-ItemProperty -Path $script:RegPath_WU -Name 'TargetReleaseVersion' -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $script:RegPath_WU -Name 'TargetReleaseVersionInfo' -Value $versionInfo -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $script:RegPath_WU -Name 'ProductVersion' -Value $productVersion -PropertyType String -Force | Out-Null
        Write-Host ""
        Write-Host "  SUCCESS: OS pinned to $productVersion $versionInfo" -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Remove-OSPin {
    Write-Host ""
    Write-Host "  --- Remove OS Version Pin ---" -ForegroundColor Cyan
    Write-Host ""
    $confirm = Read-Host "  Remove version pinning? Device will receive latest feature updates. (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    try {
        if (Test-Path $script:RegPath_WU) {
            Remove-ItemProperty -Path $script:RegPath_WU -Name 'TargetReleaseVersion' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $script:RegPath_WU -Name 'TargetReleaseVersionInfo' -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $script:RegPath_WU -Name 'ProductVersion' -ErrorAction SilentlyContinue
        }
        Write-Host "  SUCCESS: OS version pin removed." -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Set-DeferralPolicy {
    Write-Host ""
    Write-Host "  --- Set Update Deferral Periods ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Feature updates (major releases): 0-365 days" -ForegroundColor Gray
    Write-Host "  Quality updates (security/cumulative): 0-30 days" -ForegroundColor Gray
    Write-Host "  Microsoft recommends: Feature=30-90 days, Quality=3-7 days" -ForegroundColor Gray
    Write-Host ""

    $featureInput = Read-Host "  Feature update deferral days (0-365, blank to skip)"
    $qualityInput = Read-Host "  Quality update deferral days (0-30, blank to skip)"

    if ([string]::IsNullOrWhiteSpace($featureInput) -and [string]::IsNullOrWhiteSpace($qualityInput)) {
        Write-Host "  Cancelled - no values entered." -ForegroundColor Yellow
        return
    }

    try {
        Ensure-RegistryPath -Path $script:RegPath_WU

        if (-not [string]::IsNullOrWhiteSpace($featureInput)) {
            $featureDays = 0
            if (-not [int]::TryParse($featureInput, [ref]$featureDays)) {
                Write-Host "  ERROR: Enter a whole number for feature deferral days." -ForegroundColor Red
                return
            }
            if ($featureDays -lt 0 -or $featureDays -gt 365) {
                Write-Host "  ERROR: Feature deferral must be 0-365." -ForegroundColor Red
                return
            }
            New-ItemProperty -Path $script:RegPath_WU -Name 'DeferFeatureUpdatesPeriodInDays' -Value $featureDays -PropertyType DWord -Force | Out-Null
            Write-Host "  Feature update deferral set to $featureDays days." -ForegroundColor Green
        }

        if (-not [string]::IsNullOrWhiteSpace($qualityInput)) {
            $qualityDays = 0
            if (-not [int]::TryParse($qualityInput, [ref]$qualityDays)) {
                Write-Host "  ERROR: Enter a whole number for quality deferral days." -ForegroundColor Red
                return
            }
            if ($qualityDays -lt 0 -or $qualityDays -gt 30) {
                Write-Host "  ERROR: Quality deferral must be 0-30." -ForegroundColor Red
                return
            }
            New-ItemProperty -Path $script:RegPath_WU -Name 'DeferQualityUpdatesPeriodInDays' -Value $qualityDays -PropertyType DWord -Force | Out-Null
            Write-Host "  Quality update deferral set to $qualityDays days." -ForegroundColor Green
        }

        Write-Host ""
        Write-Host "  SUCCESS: Deferral policies updated." -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Set-AutoUpdateBehavior {
    Write-Host ""
    Write-Host "  --- Configure Auto-Update Behavior ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor Gray
    Write-Host "    2 - Notify before download" -ForegroundColor White
    Write-Host "    3 - Auto download, notify to install (recommended)" -ForegroundColor White
    Write-Host "    4 - Auto download and schedule install" -ForegroundColor White
    Write-Host "    5 - Allow local admin to choose" -ForegroundColor White
    Write-Host ""

    $auInput = Read-Host "  Select AU option (2-5, blank to skip)"
    if ([string]::IsNullOrWhiteSpace($auInput)) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    $auOption = 0
    if (-not [int]::TryParse($auInput, [ref]$auOption)) {
        Write-Host "  ERROR: Enter a whole number (2-5)." -ForegroundColor Red
        return
    }
    if ($auOption -lt 2 -or $auOption -gt 5) {
        Write-Host "  ERROR: Must be 2-5." -ForegroundColor Red
        return
    }

    $installDay = $null
    $installHour = $null
    if ($auOption -eq 4) {
        Write-Host ""
        Write-Host "  Schedule install day:" -ForegroundColor Gray
        Write-Host "    0 = Every day, 1 = Sunday, 2 = Monday, ... 7 = Saturday" -ForegroundColor White
        $dayInput = Read-Host "  Install day (0-7, blank for every day)"
        if (-not [string]::IsNullOrWhiteSpace($dayInput)) {
            $installDay = 0
            if (-not [int]::TryParse($dayInput, [ref]$installDay)) {
                Write-Host "  ERROR: Enter a whole number (0-7)." -ForegroundColor Red
                return
            }
        }
        else { $installDay = 0 }

        $hourInput = Read-Host "  Install hour (0-23, e.g. 3 for 3:00 AM)"
        if (-not [string]::IsNullOrWhiteSpace($hourInput)) {
            $installHour = 0
            if (-not [int]::TryParse($hourInput, [ref]$installHour)) {
                Write-Host "  ERROR: Enter a whole number (0-23)." -ForegroundColor Red
                return
            }
        }
        else { $installHour = 3 }
    }

    try {
        Ensure-RegistryPath -Path $script:RegPath_AU
        # Remove NoAutoUpdate rather than writing 0 -- "not configured" requires the value to not exist
        $noAutoUpdateCurrent = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'NoAutoUpdate'
        if ($noAutoUpdateCurrent -eq 1) {
            Remove-ItemProperty -Path $script:RegPath_AU -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue
        }
        New-ItemProperty -Path $script:RegPath_AU -Name 'AUOptions' -Value $auOption -PropertyType DWord -Force | Out-Null

        if ($null -ne $installDay) {
            New-ItemProperty -Path $script:RegPath_AU -Name 'ScheduledInstallDay' -Value $installDay -PropertyType DWord -Force | Out-Null
        }
        if ($null -ne $installHour) {
            New-ItemProperty -Path $script:RegPath_AU -Name 'ScheduledInstallTime' -Value $installHour -PropertyType DWord -Force | Out-Null
        }

        $desc = $script:AUOptionsMap[$auOption]
        Write-Host ""
        Write-Host "  SUCCESS: Auto-update set to option $auOption ($desc)" -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Set-ActiveHours {
    Write-Host ""
    Write-Host "  --- Set Active Hours ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Windows will not restart for updates during active hours." -ForegroundColor Gray
    Write-Host "  Maximum range: 18 hours. Values are 0-23 (24-hour format)." -ForegroundColor Gray
    Write-Host ""

    $startInput = Read-Host "  Active hours start (0-23, e.g. 8 for 8:00 AM)"
    if ([string]::IsNullOrWhiteSpace($startInput)) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }
    $endInput = Read-Host "  Active hours end (0-23, e.g. 17 for 5:00 PM)"
    if ([string]::IsNullOrWhiteSpace($endInput)) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    $startH = 0
    if (-not [int]::TryParse($startInput, [ref]$startH)) {
        Write-Host "  ERROR: Enter a whole number (0-23)." -ForegroundColor Red
        return
    }
    $endH = 0
    if (-not [int]::TryParse($endInput, [ref]$endH)) {
        Write-Host "  ERROR: Enter a whole number (0-23)." -ForegroundColor Red
        return
    }

    if ($startH -lt 0 -or $startH -gt 23 -or $endH -lt 0 -or $endH -gt 23) {
        Write-Host "  ERROR: Values must be 0-23." -ForegroundColor Red
        return
    }

    $span = $endH - $startH
    if ($span -lt 0) { $span = $span + 24 }
    if ($span -lt 1 -or $span -gt 18) {
        Write-Host "  ERROR: Active hours range must be 1-18 hours." -ForegroundColor Red
        return
    }

    try {
        Ensure-RegistryPath -Path $script:RegPath_AU
        New-ItemProperty -Path $script:RegPath_AU -Name 'SetActiveHours' -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $script:RegPath_AU -Name 'ActiveHoursStart' -Value $startH -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $script:RegPath_AU -Name 'ActiveHoursEnd' -Value $endH -PropertyType DWord -Force | Out-Null

        Write-Host ""
        Write-Host "  SUCCESS: Active hours set to $(Format-Hour $startH) - $(Format-Hour $endH)" -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Set-PauseUpdates {
    param([switch]$Unpause)

    if ($Unpause) {
        Write-Host ""
        Write-Host "  --- Unpause Updates ---" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  1) Feature updates only" -ForegroundColor White
        Write-Host "  2) Quality updates only" -ForegroundColor White
        Write-Host "  3) Both" -ForegroundColor White
        $typeInput = Read-Host "  Select (1-3)"

        try {
            if ($typeInput -eq '1' -or $typeInput -eq '3') {
                # GP path (policy-driven pauses)
                if (Test-Path $script:RegPath_WU) {
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesStartTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesEndTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseFeatureUpdates' -ErrorAction SilentlyContinue
                }
                # UX Settings path (user-initiated pauses)
                if (Test-Path $script:RegPath_UX) {
                    Remove-ItemProperty -Path $script:RegPath_UX -Name 'PauseFeatureUpdatesStartTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_UX -Name 'PauseFeatureUpdatesEndTime' -ErrorAction SilentlyContinue
                }
                Write-Host "  Feature updates unpaused." -ForegroundColor Green
            }
            if ($typeInput -eq '2' -or $typeInput -eq '3') {
                # GP path (policy-driven pauses)
                if (Test-Path $script:RegPath_WU) {
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseQualityUpdatesStartTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseQualityUpdatesEndTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseQualityUpdates' -ErrorAction SilentlyContinue
                }
                # UX Settings path (user-initiated pauses)
                if (Test-Path $script:RegPath_UX) {
                    Remove-ItemProperty -Path $script:RegPath_UX -Name 'PauseQualityUpdatesStartTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_UX -Name 'PauseQualityUpdatesEndTime' -ErrorAction SilentlyContinue
                }
                Write-Host "  Quality updates unpaused." -ForegroundColor Green
            }
            # PauseUpdatesExpiryTime in UX Settings is a consolidated expiry covering all update
            # types -- only safe to remove when unpausing both
            if ($typeInput -eq '3' -and (Test-Path $script:RegPath_UX)) {
                Remove-ItemProperty -Path $script:RegPath_UX -Name 'PauseUpdatesExpiryTime' -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
        return
    }

    Write-Host ""
    Write-Host "  --- Pause Updates ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  1) Feature updates only" -ForegroundColor White
    Write-Host "  2) Quality updates only" -ForegroundColor White
    Write-Host "  3) Both" -ForegroundColor White
    $typeInput = Read-Host "  Select (1-3)"

    Write-Host ""
    $daysInput = Read-Host "  Pause duration in days (1-35, default: 35)"
    if ([string]::IsNullOrWhiteSpace($daysInput)) { $pauseDays = 35 }
    else {
        $pauseDays = 0
        if (-not [int]::TryParse($daysInput, [ref]$pauseDays)) {
            Write-Host "  ERROR: Enter a whole number (1-35)." -ForegroundColor Red
            return
        }
    }

    if ($pauseDays -lt 1 -or $pauseDays -gt 35) {
        Write-Host "  ERROR: Pause duration must be 1-35 days." -ForegroundColor Red
        return
    }

    $now = [DateTime]::UtcNow
    $startStr = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $endStr = $now.AddDays($pauseDays).ToString('yyyy-MM-ddTHH:mm:ssZ')

    try {
        Ensure-RegistryPath -Path $script:RegPath_WU

        if ($typeInput -eq '1' -or $typeInput -eq '3') {
            New-ItemProperty -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesStartTime' -Value $startStr -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesEndTime' -Value $endStr -PropertyType String -Force | Out-Null
            Write-Host "  Feature updates paused for $pauseDays days." -ForegroundColor Green
        }
        if ($typeInput -eq '2' -or $typeInput -eq '3') {
            New-ItemProperty -Path $script:RegPath_WU -Name 'PauseQualityUpdatesStartTime' -Value $startStr -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $script:RegPath_WU -Name 'PauseQualityUpdatesEndTime' -Value $endStr -PropertyType String -Force | Out-Null
            Write-Host "  Quality updates paused for $pauseDays days." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ============================================================================
#  BACKUP / RESTORE
# ============================================================================

function Backup-WUSettings {
    param(
        [string]$Reason = 'manual'
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupDir = "$env:ProgramData\WUDUP\Backups"
    if (-not (Test-Path $backupDir)) {
        New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    }

    $backupFile = Join-Path $backupDir "wudup_backup_${timestamp}_${Reason}.json"

    $backup = [ordered]@{
        Timestamp     = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Reason        = $Reason
        FormatVersion = 2
        Paths         = [ordered]@{}
    }

    $pathsToBackup = @(
        @{ Name = 'WindowsUpdate';     Path = $script:RegPath_WU }
        @{ Name = 'AU';                Path = $script:RegPath_AU }
        @{ Name = 'UXSettings';        Path = $script:RegPath_UX }
        @{ Name = 'DOPolicy';          Path = $script:RegPath_DO_Policy }
        # MDM PolicyManager path is included so restores are complete. Note: if the device
        # still has an active Intune enrollment these values will be re-delivered on next
        # MDM sync and the restore will be overwritten.
        @{ Name = 'MDMUpdate';         Path = $script:RegPath_MDM }
    )

    foreach ($entry in $pathsToBackup) {
        $values = Get-RegistryValuesWithType -Path $entry.Path
        if ($values.Count -gt 0) {
            $backup.Paths[$entry.Name] = [ordered]@{
                RegistryPath = $entry.Path
                Values       = $values
            }
        }
    }

    $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $backupFile -Encoding UTF8
    return $backupFile
}

function Restore-WUSettings {
    Write-Host ""
    Write-Host "  --- Restore Settings from Backup ---" -ForegroundColor Cyan
    Write-Host ""

    $backupDir = "$env:ProgramData\WUDUP\Backups"
    if (-not (Test-Path $backupDir)) {
        Write-Host "  No backups found." -ForegroundColor Yellow
        return
    }

    $files = Get-ChildItem -Path $backupDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    if ($files.Count -eq 0) {
        Write-Host "  No backups found." -ForegroundColor Yellow
        return
    }

    Write-Host "  Available backups:" -ForegroundColor White
    for ($i = 0; $i -lt [Math]::Min($files.Count, 10); $i++) {
        $f = $files[$i]
        try {
            $content = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
            $reason = $content.Reason
            $ts = $content.Timestamp
        }
        catch {
            $reason = 'unknown'
            $ts = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        Write-Host "    [$($i + 1)]  $ts  ($reason)" -ForegroundColor White
    }

    Write-Host ""
    $selection = Read-Host "  Select backup to restore (1-$([Math]::Min($files.Count, 10)), blank to cancel)"
    if ([string]::IsNullOrWhiteSpace($selection)) {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    $idx = [int]$selection - 1
    if ($idx -lt 0 -or $idx -ge [Math]::Min($files.Count, 10)) {
        Write-Host "  Invalid selection." -ForegroundColor Yellow
        return
    }

    $selectedFile = $files[$idx]
    try {
        $backup = Get-Content -Path $selectedFile.FullName -Raw | ConvertFrom-Json
    }
    catch {
        Write-Host "  ERROR: Could not read backup file." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  This will restore settings from: $($backup.Timestamp) ($($backup.Reason))" -ForegroundColor White
    Write-Host "  Current settings will be backed up first." -ForegroundColor Gray
    Write-Host ""

    # Show what will be restored
    Write-Host "  Registry paths to restore:" -ForegroundColor White
    foreach ($pathName in $backup.Paths.PSObject.Properties.Name) {
        $pathData = $backup.Paths.$pathName
        $regPath = $pathData.RegistryPath
        $valueCount = $pathData.Values.PSObject.Properties.Name.Count
        Write-Host "    $regPath ($valueCount values)" -ForegroundColor Gray
    }

    Write-Host ""
    $confirm = Read-Host "  Proceed with restore? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    # Backup current state before restoring
    $preRestoreBackup = Backup-WUSettings -Reason 'pre-restore'
    Write-Host "  Current settings backed up to: $preRestoreBackup" -ForegroundColor DarkGray

    # FormatVersion 2 stores { Type, Data } per value; older files store raw values
    $isV2 = ($null -ne $backup.FormatVersion -and [int]$backup.FormatVersion -ge 2)

    try {
        foreach ($pathName in $backup.Paths.PSObject.Properties.Name) {
            $pathData = $backup.Paths.$pathName
            $regPath = $pathData.RegistryPath

            # Clean existing values at this path
            if (Test-Path $regPath) {
                $existing = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    $existing.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                        Remove-ItemProperty -Path $regPath -Name $_.Name -ErrorAction SilentlyContinue
                    }
                }
            }

            # Write backed-up values. For the MDMUpdate path (PolicyManager), note that if
            # the device still has an active Intune enrollment these values will be re-delivered
            # on next MDM sync and the restore will be overwritten by policy.
            Ensure-RegistryPath -Path $regPath
            foreach ($valName in $pathData.Values.PSObject.Properties.Name) {
                if ($isV2) {
                    # New format: each entry is { Type: "DWord"|"String"|..., Data: <value> }
                    $entry    = $pathData.Values.$valName
                    $typeName = $entry.Type
                    $rawData  = $entry.Data

                    $validKinds = @('String','ExpandString','Binary','DWord','MultiString','QWord')
                    if ($typeName -notin $validKinds) {
                        Write-Host "  WARNING: Unrecognized registry type '$typeName' for value '$valName' -- restoring as String." -ForegroundColor Yellow
                        $typeName = 'String'
                    }

                    $writeValue = switch ($typeName) {
                        'DWord'       { [int32][double]$rawData }
                        'QWord'       { [int64][double]$rawData }
                        'Binary'      { [Convert]::FromBase64String([string]$rawData) }
                        'MultiString' { [string[]]($rawData) }
                        default       { [string]$rawData }
                    }
                    New-ItemProperty -Path $regPath -Name $valName -Value $writeValue -PropertyType $typeName -Force | Out-Null
                }
                else {
                    # Old format: raw value with no type information
                    $val = $pathData.Values.$valName
                    if ($val -is [int] -or $val -is [long]) {
                        New-ItemProperty -Path $regPath -Name $valName -Value $val -PropertyType DWord -Force | Out-Null
                    }
                    else {
                        New-ItemProperty -Path $regPath -Name $valName -Value $val.ToString() -PropertyType String -Force | Out-Null
                    }
                }
            }
        }

        Write-Host ""
        Write-Host "  SUCCESS: Settings restored from backup." -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Pre-restore backup available at: $preRestoreBackup" -ForegroundColor Yellow
    }
}

# ============================================================================
#  SWITCH UPDATE SOURCE
# ============================================================================

function Show-SourceChangePreview {
    param(
        [string]$TargetSource,
        [array]$ToRemove,
        [array]$ToSet
    )

    Write-Host ""
    Write-Host "  --- Change Preview ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Target: $TargetSource" -ForegroundColor White
    Write-Host ""

    if ($ToRemove.Count -gt 0) {
        Write-Host "  Values to REMOVE:" -ForegroundColor Red
        foreach ($item in $ToRemove) {
            Write-Host "    [-] $($item.Path)\$($item.Name)" -ForegroundColor Red
        }
    }

    if ($ToSet.Count -gt 0) {
        Write-Host ""
        Write-Host "  Values to SET:" -ForegroundColor Green
        foreach ($item in $ToSet) {
            Write-Host "    [+] $($item.Path)\$($item.Name) = $($item.Value) ($($item.Type))" -ForegroundColor Green
        }
    }

    Write-Host ""
}

function Get-WSUSCleanupItems {
    $items = @()
    $wsusValues = @('WUServer', 'WUStatusServer', 'UpdateServiceUrlAlternate',
                    'DoNotConnectToWindowsUpdateInternetLocations', 'SetDisableUXWUAccess')
    foreach ($v in $wsusValues) {
        $current = Get-SafeRegistryValue -Path $script:RegPath_WU -Name $v
        if ($null -ne $current) {
            $items += @{ Path = $script:RegPath_WU; Name = $v }
        }
    }

    $auValues = @('UseWUServer')
    foreach ($v in $auValues) {
        $current = Get-SafeRegistryValue -Path $script:RegPath_AU -Name $v
        if ($null -ne $current) {
            $items += @{ Path = $script:RegPath_AU; Name = $v }
        }
    }

    return $items
}

function Get-WUfBCleanupItems {
    $items = @()
    $wufbValues = @('DeferFeatureUpdatesPeriodInDays', 'DeferQualityUpdatesPeriodInDays',
                    'SetPolicyDrivenUpdateSourceForFeatureUpdates', 'SetPolicyDrivenUpdateSourceForQualityUpdates',
                    'SetPolicyDrivenUpdateSourceForDriverUpdates', 'SetPolicyDrivenUpdateSourceForOtherUpdates',
                    'ConfigureDeadlineForFeatureUpdates', 'ConfigureDeadlineForQualityUpdates',
                    'ConfigureDeadlineGracePeriod', 'ConfigureDeadlineGracePeriodForFeatureUpdates',
                    'ComplianceDeadlineForFU', 'ComplianceDeadline',
                    'ComplianceGracePeriod', 'ComplianceGracePeriodForFU',
                    'TargetReleaseVersion', 'TargetReleaseVersionInfo', 'ProductVersion',
                    'BranchReadinessLevel', 'ManagePreviewBuilds',
                    'ExcludeWUDriversInQualityUpdate')
    foreach ($v in $wufbValues) {
        $current = Get-SafeRegistryValue -Path $script:RegPath_WU -Name $v
        if ($null -ne $current) {
            $items += @{ Path = $script:RegPath_WU; Name = $v }
        }
    }

    $auValues = @('UseUpdateClassPolicySource')
    foreach ($v in $auValues) {
        $current = Get-SafeRegistryValue -Path $script:RegPath_AU -Name $v
        if ($null -ne $current) {
            $items += @{ Path = $script:RegPath_AU; Name = $v }
        }
    }

    # MDM PolicyManager path -- same WUfB indicator values delivered via CSP.
    # Note: if the device still has an active Intune enrollment these values will be
    # re-delivered on next MDM sync. Cleanup here prevents dual-scan immediately after
    # the switch but Intune policy must also be updated for a permanent change.
    $mdmValues = @('DeferFeatureUpdatesPeriodInDays', 'DeferQualityUpdatesPeriodInDays',
                   'SetPolicyDrivenUpdateSourceForFeatureUpdates', 'SetPolicyDrivenUpdateSourceForQualityUpdates',
                   'SetPolicyDrivenUpdateSourceForDriverUpdates', 'SetPolicyDrivenUpdateSourceForOtherUpdates',
                   'ConfigureDeadlineForFeatureUpdates', 'ConfigureDeadlineForQualityUpdates',
                   'ConfigureDeadlineGracePeriod', 'ConfigureDeadlineGracePeriodForFeatureUpdates',
                   'TargetReleaseVersion', 'TargetReleaseVersionInfo', 'ProductVersion',
                   'BranchReadinessLevel', 'ManagePreviewBuilds',
                   'ExcludeWUDriversInQualityUpdate')
    foreach ($v in $mdmValues) {
        $current = Get-SafeRegistryValue -Path $script:RegPath_MDM -Name $v
        if ($null -ne $current) {
            $items += @{ Path = $script:RegPath_MDM; Name = $v }
        }
    }

    return $items
}

function Get-GPOCleanupItems {
    $items = @()
    if (Test-Path $script:RegPath_WU) {
        $props = Get-ItemProperty -Path $script:RegPath_WU -ErrorAction SilentlyContinue
        if ($null -ne $props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $items += @{ Path = $script:RegPath_WU; Name = $_.Name }
            }
        }
    }
    if (Test-Path $script:RegPath_AU) {
        $props = Get-ItemProperty -Path $script:RegPath_AU -ErrorAction SilentlyContinue
        if ($null -ne $props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $items += @{ Path = $script:RegPath_AU; Name = $_.Name }
            }
        }
    }
    return $items
}

function Get-PauseCleanupItems {
    $items = @()
    $pauseValues = @('PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
                     'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime',
                     'PauseFeatureUpdates', 'PauseQualityUpdates')
    foreach ($v in $pauseValues) {
        $current = Get-SafeRegistryValue -Path $script:RegPath_WU -Name $v
        if ($null -ne $current) {
            $items += @{ Path = $script:RegPath_WU; Name = $v }
        }
    }
    return $items
}

function Switch-ToWUfB {
    Write-Host ""
    Write-Host "  --- Switch to Windows Update for Business ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  WUfB uses Microsoft Update with deferral policies (no WSUS)." -ForegroundColor Gray
    Write-Host "  This will remove any WSUS configuration and set deferral policies." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTE: If this device is managed by Group Policy or MDM, those policies" -ForegroundColor Yellow
    Write-Host "  will overwrite these local changes on the next sync cycle." -ForegroundColor Yellow
    Write-Host "  For a permanent switch, update your GPO/Intune policies." -ForegroundColor Yellow
    Write-Host ""

    # Collect what needs to change
    $toRemove = @()
    $toRemove += Get-WSUSCleanupItems
    $toRemove += Get-PauseCleanupItems

    # Also remove DoNotConnectToWindowsUpdateInternetLocations (must be off for WUfB)
    # Already included in WSUS cleanup

    # Gather desired WUfB settings
    Write-Host "  --- WUfB Deferral Configuration ---" -ForegroundColor White
    Write-Host ""
    Write-Host "  Microsoft recommends: Feature=30-90 days, Quality=3-7 days" -ForegroundColor Gray
    Write-Host ""

    $featureInput = Read-Host "  Feature update deferral days (0-365, default: 30)"
    if ([string]::IsNullOrWhiteSpace($featureInput)) { $featureDays = 30 }
    else { $featureDays = [int]$featureInput }
    if ($featureDays -lt 0 -or $featureDays -gt 365) {
        Write-Host "  ERROR: Feature deferral must be 0-365." -ForegroundColor Red
        return
    }

    $qualityInput = Read-Host "  Quality update deferral days (0-30, default: 7)"
    if ([string]::IsNullOrWhiteSpace($qualityInput)) { $qualityDays = 7 }
    else { $qualityDays = [int]$qualityInput }
    if ($qualityDays -lt 0 -or $qualityDays -gt 30) {
        Write-Host "  ERROR: Quality deferral must be 0-30." -ForegroundColor Red
        return
    }

    # Optional version pin
    Write-Host ""
    $pinChoice = Read-Host "  Pin to a specific OS version? (Y/N, default: N)"
    $pinVersion = $null
    $pinProduct = $null
    if ($pinChoice -eq 'Y' -or $pinChoice -eq 'y') {
        $currentOS = Get-OSInfo
        $defaultProduct = 'Windows 10'
        if ($currentOS.Caption -like '*Windows 11*') { $defaultProduct = 'Windows 11' }

        Write-Host "  Product options:  1) Windows 10   2) Windows 11" -ForegroundColor White
        $prodChoice = Read-Host "  Select product [default: $defaultProduct]"
        if ($prodChoice -eq '1') { $pinProduct = 'Windows 10' }
        elseif ($prodChoice -eq '2') { $pinProduct = 'Windows 11' }
        else { $pinProduct = $defaultProduct }

        Write-Host "  Common versions:  21H2, 22H2, 23H2, 24H2" -ForegroundColor White
        $pinVersion = Read-Host "  Enter target version (e.g., 24H2)"
        if ([string]::IsNullOrWhiteSpace($pinVersion)) {
            $pinVersion = $null
            $pinProduct = $null
        }
    }

    # Auto-update behavior
    Write-Host ""
    Write-Host "  Auto-update behavior:" -ForegroundColor White
    Write-Host "    3 - Auto download, notify to install (recommended for WUfB)" -ForegroundColor White
    Write-Host "    4 - Auto download and schedule install" -ForegroundColor White
    Write-Host "    5 - Allow local admin to choose" -ForegroundColor White
    $auInput = Read-Host "  Select AU option (2-5, default: 3)"
    if ([string]::IsNullOrWhiteSpace($auInput)) { $auOption = 3 }
    else { $auOption = [int]$auInput }
    if ($auOption -lt 2 -or $auOption -gt 5) {
        Write-Host "  ERROR: Must be 2-5." -ForegroundColor Red
        return
    }

    # Compliance deadlines (optional)
    Write-Host ""
    $deadlineChoice = Read-Host "  Configure compliance deadlines? (Y/N, default: N)"
    $deadlineFeature = $null
    $deadlineQuality = $null
    $deadlineGrace = $null
    if ($deadlineChoice -eq 'Y' -or $deadlineChoice -eq 'y') {
        Write-Host ""
        Write-Host "  Compliance deadlines force install after deferral + deadline period." -ForegroundColor Gray
        $dlFeatureInput = Read-Host "  Feature update deadline days (0-30, default: 7)"
        if ([string]::IsNullOrWhiteSpace($dlFeatureInput)) { $deadlineFeature = 7 }
        else { $deadlineFeature = [int]$dlFeatureInput }

        $dlQualityInput = Read-Host "  Quality update deadline days (0-30, default: 3)"
        if ([string]::IsNullOrWhiteSpace($dlQualityInput)) { $deadlineQuality = 3 }
        else { $deadlineQuality = [int]$dlQualityInput }

        $dlGraceInput = Read-Host "  Grace period days (0-7, default: 2)"
        if ([string]::IsNullOrWhiteSpace($dlGraceInput)) { $deadlineGrace = 2 }
        else { $deadlineGrace = [int]$dlGraceInput }
    }

    # Build the set list
    $toSet = @()

    # PolicyDrivenSource keys -- explicitly direct updates to Windows Update (value 0)
    # These are the most definitive WUfB signal on Windows 10 2004+ / Windows 11
    $toSet += @{ Path = $script:RegPath_WU; Name = 'SetPolicyDrivenUpdateSourceForFeatureUpdates'; Value = 0; Type = 'DWord' }
    $toSet += @{ Path = $script:RegPath_WU; Name = 'SetPolicyDrivenUpdateSourceForQualityUpdates'; Value = 0; Type = 'DWord' }
    $toSet += @{ Path = $script:RegPath_WU; Name = 'SetPolicyDrivenUpdateSourceForDriverUpdates'; Value = 0; Type = 'DWord' }
    $toSet += @{ Path = $script:RegPath_WU; Name = 'SetPolicyDrivenUpdateSourceForOtherUpdates'; Value = 0; Type = 'DWord' }
    # Required for PolicyDrivenSource to take effect when set via direct registry write (not GPO/CSP)
    $toSet += @{ Path = $script:RegPath_AU; Name = 'UseUpdateClassPolicySource'; Value = 1; Type = 'DWord' }

    $toSet += @{ Path = $script:RegPath_WU; Name = 'DeferFeatureUpdatesPeriodInDays'; Value = $featureDays; Type = 'DWord' }
    $toSet += @{ Path = $script:RegPath_WU; Name = 'DeferQualityUpdatesPeriodInDays'; Value = $qualityDays; Type = 'DWord' }
    $toSet += @{ Path = $script:RegPath_AU; Name = 'AUOptions'; Value = $auOption; Type = 'DWord' }

    # Remove update-disabling blockers (matches PR remediate logic)
    $noAutoUpdateCurrent = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdateCurrent -eq 1) {
        $toRemove += @{ Path = $script:RegPath_AU; Name = 'NoAutoUpdate' }
    }
    # AUOptions=1 means "Never check" -- remove it so the user-chosen value takes effect
    $auOptionsCurrent = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'AUOptions'
    if ($auOptionsCurrent -eq 1) {
        $toRemove += @{ Path = $script:RegPath_AU; Name = 'AUOptions' }
    }

    # Compliance deadlines
    if ($null -ne $deadlineFeature) {
        $toSet += @{ Path = $script:RegPath_WU; Name = 'ConfigureDeadlineForFeatureUpdates'; Value = $deadlineFeature; Type = 'DWord' }
        $toSet += @{ Path = $script:RegPath_WU; Name = 'ConfigureDeadlineForQualityUpdates'; Value = $deadlineQuality; Type = 'DWord' }
        $toSet += @{ Path = $script:RegPath_WU; Name = 'ConfigureDeadlineGracePeriod'; Value = $deadlineGrace; Type = 'DWord' }
    }

    if ($null -ne $pinVersion) {
        $toSet += @{ Path = $script:RegPath_WU; Name = 'TargetReleaseVersion'; Value = 1; Type = 'DWord' }
        $toSet += @{ Path = $script:RegPath_WU; Name = 'TargetReleaseVersionInfo'; Value = $pinVersion; Type = 'String' }
        $toSet += @{ Path = $script:RegPath_WU; Name = 'ProductVersion'; Value = $pinProduct; Type = 'String' }
    }

    # Preview
    Show-SourceChangePreview -TargetSource 'Windows Update for Business (WUfB)' -ToRemove $toRemove -ToSet $toSet

    $confirm = Read-Host "  Apply these changes? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    # Backup first
    $backupFile = Backup-WUSettings -Reason 'pre-switch-to-wufb'
    Write-Host "  Settings backed up to: $backupFile" -ForegroundColor DarkGray

    try {
        # Remove old values
        foreach ($item in $toRemove) {
            if (Test-Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue
            }
        }

        # Set new values
        foreach ($item in $toSet) {
            Ensure-RegistryPath -Path $item.Path
            if ($item.Type -eq 'DWord') {
                New-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -PropertyType DWord -Force | Out-Null
            }
            else {
                New-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -PropertyType String -Force | Out-Null
            }
        }

        # Re-enable Windows Update services if disabled (matches PR remediate logic)
        $svcNames = @('wuauserv', 'UsoSvc')
        foreach ($svcName in $svcNames) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($null -ne $svc -and $svc.StartType -eq 'Disabled') {
                Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue
                Write-Host "  Re-enabled $svcName service (was Disabled)" -ForegroundColor Yellow
            }
        }

        # Trigger scan to pick up new policies
        try {
            Start-Process -FilePath 'usoclient' -ArgumentList 'StartScan' -NoNewWindow -Wait -ErrorAction Stop
        }
        catch { }

        Write-Host ""
        Write-Host "  SUCCESS: Switched to WUfB configuration." -ForegroundColor Green
        Write-Host "  Feature deferral: $featureDays days, Quality deferral: $qualityDays days" -ForegroundColor Green
        if ($null -ne $pinVersion) {
            Write-Host "  Pinned to: $pinProduct $pinVersion" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Backup available at: $backupFile" -ForegroundColor Yellow
    }
}

function Switch-ToWSUS {
    Write-Host ""
    Write-Host "  --- Switch to WSUS ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This configures the device to pull updates from a WSUS server." -ForegroundColor Gray
    Write-Host "  WUfB deferral policies will be removed to avoid dual-scan issues." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTE: If this device is managed by Group Policy or MDM, those policies" -ForegroundColor Yellow
    Write-Host "  will overwrite these local changes on the next sync cycle." -ForegroundColor Yellow
    Write-Host ""

    $wuServer = Read-Host "  WSUS Server URL (e.g., http://wsus.contoso.com:8530)"
    if ([string]::IsNullOrWhiteSpace($wuServer)) {
        Write-Host "  Cancelled - no server entered." -ForegroundColor Yellow
        return
    }
    $parsedUri = $null
    if (-not [Uri]::TryCreate($wuServer, [UriKind]::Absolute, [ref]$parsedUri) -or
        ($parsedUri.Scheme -ne 'http' -and $parsedUri.Scheme -ne 'https') -or
        [string]::IsNullOrWhiteSpace($parsedUri.Host)) {
        Write-Host "  ERROR: Enter a valid URL starting with http:// or https:// (e.g., http://wsus.contoso.com:8530)." -ForegroundColor Red
        return
    }

    $statusServer = Read-Host "  WSUS Status Server URL (blank = same as WSUS server)"
    if ([string]::IsNullOrWhiteSpace($statusServer)) { $statusServer = $wuServer }

    # Collect WUfB values to remove (avoid dual-scan)
    $toRemove = @()
    $toRemove += Get-WUfBCleanupItems
    $toRemove += Get-PauseCleanupItems

    $toSet = @()
    $toSet += @{ Path = $script:RegPath_WU; Name = 'WUServer'; Value = $wuServer; Type = 'String' }
    $toSet += @{ Path = $script:RegPath_WU; Name = 'WUStatusServer'; Value = $statusServer; Type = 'String' }
    $toSet += @{ Path = $script:RegPath_AU; Name = 'UseWUServer'; Value = 1; Type = 'DWord' }

    # AU behavior
    Write-Host ""
    Write-Host "  Auto-update behavior:" -ForegroundColor White
    Write-Host "    3 - Auto download, notify to install" -ForegroundColor White
    Write-Host "    4 - Auto download and schedule install (recommended for WSUS)" -ForegroundColor White
    Write-Host "    5 - Allow local admin to choose" -ForegroundColor White
    $auInput = Read-Host "  Select AU option (2-5, default: 4)"
    if ([string]::IsNullOrWhiteSpace($auInput)) { $auOption = 4 }
    else { $auOption = [int]$auInput }
    if ($auOption -lt 2 -or $auOption -gt 5) {
        Write-Host "  ERROR: Must be 2-5." -ForegroundColor Red
        return
    }

    # Remove update-disabling blockers
    $noAutoUpdateCurrent = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdateCurrent -eq 1) {
        $toRemove += @{ Path = $script:RegPath_AU; Name = 'NoAutoUpdate' }
    }
    $auOptionsCurrent = Get-SafeRegistryValue -Path $script:RegPath_AU -Name 'AUOptions'
    if ($auOptionsCurrent -eq 1) {
        $toRemove += @{ Path = $script:RegPath_AU; Name = 'AUOptions' }
    }
    $toSet += @{ Path = $script:RegPath_AU; Name = 'AUOptions'; Value = $auOption; Type = 'DWord' }

    Show-SourceChangePreview -TargetSource "WSUS ($wuServer)" -ToRemove $toRemove -ToSet $toSet

    $confirm = Read-Host "  Apply these changes? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    $backupFile = Backup-WUSettings -Reason 'pre-switch-to-wsus'
    Write-Host "  Settings backed up to: $backupFile" -ForegroundColor DarkGray

    try {
        foreach ($item in $toRemove) {
            if (Test-Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue
            }
        }

        foreach ($item in $toSet) {
            Ensure-RegistryPath -Path $item.Path
            if ($item.Type -eq 'DWord') {
                New-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -PropertyType DWord -Force | Out-Null
            }
            else {
                New-ItemProperty -Path $item.Path -Name $item.Name -Value $item.Value -PropertyType String -Force | Out-Null
            }
        }

        # Re-enable Windows Update services if disabled
        $svcNames = @('wuauserv', 'UsoSvc')
        foreach ($svcName in $svcNames) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($null -ne $svc -and $svc.StartType -eq 'Disabled') {
                Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue
                Write-Host "  Re-enabled $svcName service (was Disabled)" -ForegroundColor Yellow
            }
        }

        # Trigger scan to pick up new policies
        try {
            Start-Process -FilePath 'usoclient' -ArgumentList 'StartScan' -NoNewWindow -Wait -ErrorAction Stop
        }
        catch { }

        Write-Host ""
        Write-Host "  SUCCESS: Switched to WSUS ($wuServer)." -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Backup available at: $backupFile" -ForegroundColor Yellow
    }
}

function Switch-ToMicrosoftUpdate {
    Write-Host ""
    Write-Host "  --- Switch to Microsoft Update (Direct) ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  This removes all WSUS and WUfB policy settings, returning the device" -ForegroundColor Gray
    Write-Host "  to default Windows Update behavior (direct from Microsoft)." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  NOTE: If this device is managed by Group Policy, SCCM, or MDM," -ForegroundColor Yellow
    Write-Host "  those policies will re-apply on the next sync cycle." -ForegroundColor Yellow
    Write-Host ""

    $toRemove = Get-GPOCleanupItems

    if ($toRemove.Count -eq 0) {
        Write-Host "  No policy settings found to remove. Device is already using defaults." -ForegroundColor Green
        return
    }

    Show-SourceChangePreview -TargetSource 'Microsoft Update (direct, no policies)' -ToRemove $toRemove -ToSet @()

    $confirm = Read-Host "  Apply these changes? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "  Cancelled." -ForegroundColor Yellow
        return
    }

    $backupFile = Backup-WUSettings -Reason 'pre-switch-to-mu-direct'
    Write-Host "  Settings backed up to: $backupFile" -ForegroundColor DarkGray

    try {
        foreach ($item in $toRemove) {
            if (Test-Path $item.Path) {
                Remove-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue
            }
        }

        # Re-enable Windows Update services if disabled
        $svcNames = @('wuauserv', 'UsoSvc')
        foreach ($svcName in $svcNames) {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($null -ne $svc -and $svc.StartType -eq 'Disabled') {
                Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue
                Write-Host "  Re-enabled $svcName service (was Disabled)" -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "  SUCCESS: All update policies removed. Using Microsoft Update defaults." -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "  Backup available at: $backupFile" -ForegroundColor Yellow
    }
}

function Show-SwitchSourceMenu {
    Write-Host ""
    Write-Host ("  " + ("=" * 72)) -ForegroundColor DarkCyan
    Write-Host "    SWITCH UPDATE SOURCE" -ForegroundColor White
    Write-Host ("  " + ("=" * 72)) -ForegroundColor DarkCyan
    Write-Host ""

    # Show current state
    $currentAuth = Get-ManagementAuthority
    Write-Host "  Current source: $($currentAuth.Authority)" -ForegroundColor White
    Write-Host "  $($currentAuth.Details)" -ForegroundColor DarkGray

    if ($currentAuth.IsSCCMManaged -or $currentAuth.IsMDMManaged) {
        Write-Host ""
        Write-Host "  WARNING: This device is managed by $($currentAuth.Authority)." -ForegroundColor Red
        Write-Host "  Local registry changes will likely be overwritten on the next policy sync." -ForegroundColor Red
        Write-Host "  To permanently switch, update policies in your management console" -ForegroundColor Red
        if ($currentAuth.IsSCCMManaged) {
            Write-Host "  (SCCM/ConfigMgr console or co-management workload settings)." -ForegroundColor Red
        }
        elseif ($currentAuth.IsMDMManaged) {
            Write-Host "  (Intune/MDM portal > Device Configuration > Update Rings)." -ForegroundColor Red
        }
        Write-Host ""
        $proceed = Read-Host "  Continue anyway? (Y/N)"
        if ($proceed -ne 'Y' -and $proceed -ne 'y') {
            Write-Host "  Cancelled." -ForegroundColor Yellow
            return
        }
    }

    Write-Host ""
    Write-Host "  Available targets:" -ForegroundColor White
    Write-Host "    [1]  Windows Update for Business (WUfB)" -ForegroundColor White
    Write-Host "         Deferrals + Microsoft Update. Best for cloud-managed devices." -ForegroundColor DarkGray
    Write-Host "    [2]  WSUS" -ForegroundColor White
    Write-Host "         On-premises update server. Traditional enterprise management." -ForegroundColor DarkGray
    Write-Host "    [3]  Microsoft Update (direct, no policies)" -ForegroundColor White
    Write-Host "         Remove all policies. Default consumer behavior." -ForegroundColor DarkGray
    Write-Host "    [4]  Restore from backup" -ForegroundColor White
    Write-Host "         Roll back to a previously saved configuration." -ForegroundColor DarkGray
    Write-Host "    [0]  Cancel" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "  Select target"

    switch ($choice) {
        '1' { Switch-ToWUfB }
        '2' { Switch-ToWSUS }
        '3' { Switch-ToMicrosoftUpdate }
        '4' { Restore-WUSettings }
        '0' { }
        default { Write-Host "  Invalid selection." -ForegroundColor Yellow }
    }
}

# ============================================================================
#  MODIFICATION MENU
# ============================================================================

function Show-ModificationMenu {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Authority
    )

    do {
        Write-Host ""
        Write-Host ("  " + ("=" * 72)) -ForegroundColor DarkCyan
        Write-Host "    MODIFICATION MENU" -ForegroundColor White
        Write-Host ("  " + ("=" * 72)) -ForegroundColor DarkCyan

        if (-not $Authority.CanModify) {
            Write-Host ""
            Write-Host "    WARNING: This device is managed by $($Authority.Authority)." -ForegroundColor Red
            Write-Host "    Local changes may be overwritten on next policy sync." -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "    [1]  Set OS Version Pin" -ForegroundColor White
        Write-Host "    [2]  Remove OS Version Pin" -ForegroundColor White
        Write-Host "    [3]  Set Deferral Periods" -ForegroundColor White
        Write-Host "    [4]  Configure Auto-Update Behavior" -ForegroundColor White
        Write-Host "    [5]  Set Active Hours" -ForegroundColor White
        Write-Host "    [6]  Pause Updates" -ForegroundColor White
        Write-Host "    [7]  Unpause Updates" -ForegroundColor White
        Write-Host ""
        Write-Host "    [S]  Switch Update Source (WUfB / WSUS / Direct)" -ForegroundColor Cyan
        Write-Host "    [B]  Backup Current Settings" -ForegroundColor Cyan
        Write-Host "    [R]  Restore Settings from Backup" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    [8]  Refresh Report" -ForegroundColor White
        Write-Host "    [0]  Exit" -ForegroundColor White
        Write-Host ""

        $choice = (Read-Host "    Enter choice").ToUpper()

        switch ($choice) {
            '1' { Set-OSPin }
            '2' { Remove-OSPin }
            '3' { Set-DeferralPolicy }
            '4' { Set-AutoUpdateBehavior }
            '5' { Set-ActiveHours }
            '6' { Set-PauseUpdates }
            '7' { Set-PauseUpdates -Unpause }
            'S' { Show-SwitchSourceMenu }
            'B' {
                $backupFile = Backup-WUSettings -Reason 'manual'
                Write-Host ""
                Write-Host "  SUCCESS: Settings backed up to:" -ForegroundColor Green
                Write-Host "  $backupFile" -ForegroundColor White
            }
            'R' { Restore-WUSettings }
            '8' {
                $osInfo         = Get-OSInfo
                $authority      = Get-ManagementAuthority
                $policies       = Get-UpdatePolicies
                $serviceState   = Get-WUServiceState
                $updateStatus   = Get-UpdateStatus
                $updateHistory  = Get-RecentUpdateHistory
                $updateServices = Get-RegisteredUpdateServices
                Show-UpdateReport -OSInfo $osInfo -Authority $authority -Policies $policies -ServiceState $serviceState -UpdateStatus $updateStatus -UpdateHistory $updateHistory -UpdateServices $updateServices
            }
            '0' { }
            default {
                Write-Host "    Invalid selection." -ForegroundColor Yellow
            }
        }
    } while ($choice -ne '0')
}

# ============================================================================
#  MAIN ENTRY POINT
# ============================================================================

$isAdmin = Test-IsAdmin

if (-not $Report) {
    Write-Host ""
    Write-Host "  Collecting Windows Update configuration..." -ForegroundColor Cyan
}

$osInfo         = Get-OSInfo
$authority      = Get-ManagementAuthority
$policies       = Get-UpdatePolicies
$serviceState   = Get-WUServiceState
$updateStatus   = Get-UpdateStatus
$updateHistory  = Get-RecentUpdateHistory
$updateServices = Get-RegisteredUpdateServices

if ($Report) {
    # Structured output for automation
    [PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        Timestamp          = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        OSInfo             = $osInfo
        ManagementAuthority = $authority
        Policies           = $policies
        ServiceState       = $serviceState
        UpdateStatus       = $updateStatus
        UpdateHistory      = $updateHistory
        RegisteredServices = $updateServices
    }
    exit 0
}

Show-UpdateReport -OSInfo $osInfo -Authority $authority -Policies $policies -ServiceState $serviceState -UpdateStatus $updateStatus -UpdateHistory $updateHistory -UpdateServices $updateServices

if ($isAdmin) {
    Write-Host "  Running as Administrator - modification options available." -ForegroundColor Green
    Write-Host ""
    $proceed = Read-Host "  Would you like to modify settings? (Y/N)"
    if ($proceed -eq 'Y' -or $proceed -eq 'y') {
        Show-ModificationMenu -Authority $authority
    }
}
else {
    Write-Host "  NOTE: Run as Administrator to enable modification options." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "  Done." -ForegroundColor Cyan
Write-Host ""
