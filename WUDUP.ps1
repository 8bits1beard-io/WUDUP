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
    Author:  Device-DNA Project
    Tool:    WUDUP v1.0.0
    Requires: Windows 10 or Windows 11, Administrator for modifications
#>

# ============================================================================
#  REGISTRY PATH CONSTANTS
# ============================================================================

$script:RegPath_WU        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$script:RegPath_AU        = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$script:RegPath_MDM       = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
$script:RegPath_UX        = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$script:RegPath_Pause     = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings'
$script:RegPath_PolicySt  = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState'
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
    1 = 'Never check for updates (not recommended)'
    2 = 'Notify before download'
    3 = 'Auto download, notify to install'
    4 = 'Auto download and schedule install'
    5 = 'Allow local admin to choose'
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
        Status    = 'Unknown'
        StartType = 'Unknown'
    }
    try {
        $svc = Get-Service -Name 'wuauserv' -ErrorAction Stop
        $result.Status = $svc.Status.ToString()
        $result.StartType = $svc.StartType.ToString()
    }
    catch { }
    return $result
}

function Get-UpdateStatus {
    $rebootWU = Test-Path "$script:RegPath_WUAutoUpdate\RebootRequired"
    $rebootCBS = Test-Path "$script:RegPath_CBS\RebootPending"
    $lastInstall = Get-SafeRegistryValue -Path "$script:RegPath_WUAutoUpdate\Results\Install" -Name 'LastSuccessTime'
    $lastDetect = Get-SafeRegistryValue -Path "$script:RegPath_WUAutoUpdate\Results\Detect" -Name 'LastSuccessTime'
    return [PSCustomObject]@{
        RebootRequired   = ($rebootWU -or $rebootCBS)
        RebootRequiredWU = $rebootWU
        RebootRequiredCBS = $rebootCBS
        LastInstallTime  = $lastInstall
        LastDetectTime   = $lastDetect
    }
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
        CanModify     = $true
        MDMProvider   = $null
    }

    # Check SCCM/ConfigMgr
    $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
    $ccmKey = Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'
    $sccmDetected = ($null -ne $sccmService -and $ccmKey)

    # Check co-management — is the WU workload shifted to Intune?
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

    # Check MDM/Intune — verify active enrollment before trusting PolicyManager values
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
            # MDM policy keys exist but no active enrollment — likely stale
            if (-not $result.IsSCCMManaged) {
                $result.Authority = 'MDM (stale?)'
                $result.Details = 'MDM policy keys found but no active enrollment detected — may be leftover'
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

    # Check Group Policy — distinguish traditional GPO from WUfB
    if ($result.Authority -eq 'Local' -or $result.Authority -eq 'MDM (stale?)') {
        $gpValues = Get-AllRegistryValues -Path $script:RegPath_WU
        $auValues = Get-AllRegistryValues -Path $script:RegPath_AU
        if ($gpValues.Count -gt 0 -or $auValues.Count -gt 0) {
            # WUfB indicator: deferral policies present without WSUS
            $hasDeferrals = ($null -ne $gpValues['DeferFeatureUpdatesPeriodInDays'] -or
                             $null -ne $gpValues['DeferQualityUpdatesPeriodInDays'])
            $hasWSUS = ($useWU -eq 1 -and $null -ne $wuServer)

            if ($hasDeferrals -and -not $hasWSUS) {
                $result.Authority = 'WUfB (Group Policy)'
                $result.Details = 'Windows Update for Business deferral policies detected via Group Policy'
                $result.IsWUfB = $true
            }
            else {
                $result.Authority = 'Group Policy'
                $result.Details = 'Traditional Windows Update policies applied via Group Policy'
            }
            $result.IsGPOManaged = $true
            $result.CanModify = $true
        }
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
    $doGP  = Get-SafeRegistryValue -Path $script:RegPath_DO_Policy -Name 'DODownloadMode'
    $doMDM = Get-SafeRegistryValue -Path $script:RegPath_DO_MDM -Name 'DODownloadMode'
    if ($null -ne $doGP)       { $doMode = $doGP;  $doSource = 'Group Policy' }
    elseif ($null -ne $doMDM)  { $doMode = $doMDM; $doSource = 'MDM' }
    else                       { $doMode = $null;   $doSource = 'Default (OS-managed)' }

    # --- Dual-Scan Detection ---
    $dualScan = $false
    if ($useWUServer -eq 1 -and ($null -ne $gpFeatureDefer -or $null -ne $gpQualityDefer)) {
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
        # Deferrals
        FeatureDeferralDays      = $featureDefer
        FeatureDeferralSource    = $featureSource
        QualityDeferralDays      = $qualityDefer
        QualityDeferralSource    = $qualitySource
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
        [PSCustomObject]$UpdateStatus
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
        $coMgmtLabel = if ($Authority.Authority -like '*via Intune*') { 'WU workload shifted to Intune' } else { 'WU workload remains with SCCM' }
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
    Write-ReportLine "Service Status" $ServiceState.Status $svcColor
    Write-ReportLine "Start Type" $ServiceState.StartType $svcColor
    if ($ServiceState.StartType -eq 'Disabled') {
        Write-Host ""
        Write-Host "    WARNING: Windows Update service is disabled - no updates will be processed." -ForegroundColor Red
    }

    # --- Update Status ---
    Write-Section "Update Status"
    if ($UpdateStatus.RebootRequired) {
        $rebootDetail = @()
        if ($UpdateStatus.RebootRequiredWU) { $rebootDetail += 'Windows Update' }
        if ($UpdateStatus.RebootRequiredCBS) { $rebootDetail += 'Component Servicing' }
        Write-ReportLine "Pending Reboot" "YES ($($rebootDetail -join ', '))" 'Red'
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
        Write-ReportLine "Dual Scan" "DETECTED - WSUS + WUfB deferrals both active" 'Red'
        Write-Host "    WARNING: Dual scan can cause unexpected update behavior. Feature/quality" -ForegroundColor Yellow
        Write-Host "    updates may bypass WSUS and come directly from Microsoft Update." -ForegroundColor Yellow
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
            # Could not parse date — do not assume paused
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
    Write-Host "  Quality updates (security/cumulative): 0-35 days" -ForegroundColor Gray
    Write-Host "  Microsoft recommends: Feature=30-90 days, Quality=3-7 days" -ForegroundColor Gray
    Write-Host ""

    $featureInput = Read-Host "  Feature update deferral days (0-365, blank to skip)"
    $qualityInput = Read-Host "  Quality update deferral days (0-35, blank to skip)"

    if ([string]::IsNullOrWhiteSpace($featureInput) -and [string]::IsNullOrWhiteSpace($qualityInput)) {
        Write-Host "  Cancelled - no values entered." -ForegroundColor Yellow
        return
    }

    try {
        Ensure-RegistryPath -Path $script:RegPath_WU

        if (-not [string]::IsNullOrWhiteSpace($featureInput)) {
            $featureDays = [int]$featureInput
            if ($featureDays -lt 0 -or $featureDays -gt 365) {
                Write-Host "  ERROR: Feature deferral must be 0-365." -ForegroundColor Red
                return
            }
            New-ItemProperty -Path $script:RegPath_WU -Name 'DeferFeatureUpdatesPeriodInDays' -Value $featureDays -PropertyType DWord -Force | Out-Null
            Write-Host "  Feature update deferral set to $featureDays days." -ForegroundColor Green
        }

        if (-not [string]::IsNullOrWhiteSpace($qualityInput)) {
            $qualityDays = [int]$qualityInput
            if ($qualityDays -lt 0 -or $qualityDays -gt 35) {
                Write-Host "  ERROR: Quality deferral must be 0-35." -ForegroundColor Red
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

    $auOption = [int]$auInput
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
        if (-not [string]::IsNullOrWhiteSpace($dayInput)) { $installDay = [int]$dayInput }
        else { $installDay = 0 }

        $hourInput = Read-Host "  Install hour (0-23, e.g. 3 for 3:00 AM)"
        if (-not [string]::IsNullOrWhiteSpace($hourInput)) { $installHour = [int]$hourInput }
        else { $installHour = 3 }
    }

    try {
        Ensure-RegistryPath -Path $script:RegPath_AU
        New-ItemProperty -Path $script:RegPath_AU -Name 'NoAutoUpdate' -Value 0 -PropertyType DWord -Force | Out-Null
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

    $startH = [int]$startInput
    $endH = [int]$endInput

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
                if (Test-Path $script:RegPath_WU) {
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesStartTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseFeatureUpdatesEndTime' -ErrorAction SilentlyContinue
                }
                Write-Host "  Feature updates unpaused." -ForegroundColor Green
            }
            if ($typeInput -eq '2' -or $typeInput -eq '3') {
                if (Test-Path $script:RegPath_WU) {
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseQualityUpdatesStartTime' -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $script:RegPath_WU -Name 'PauseQualityUpdatesEndTime' -ErrorAction SilentlyContinue
                }
                Write-Host "  Quality updates unpaused." -ForegroundColor Green
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
    else { $pauseDays = [int]$daysInput }

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
        Write-Host "    [8]  Refresh Report" -ForegroundColor White
        Write-Host "    [0]  Exit" -ForegroundColor White
        Write-Host ""

        $choice = Read-Host "    Enter choice"

        switch ($choice) {
            '1' { Set-OSPin }
            '2' { Remove-OSPin }
            '3' { Set-DeferralPolicy }
            '4' { Set-AutoUpdateBehavior }
            '5' { Set-ActiveHours }
            '6' { Set-PauseUpdates }
            '7' { Set-PauseUpdates -Unpause }
            '8' {
                $osInfo       = Get-OSInfo
                $authority    = Get-ManagementAuthority
                $policies     = Get-UpdatePolicies
                $serviceState = Get-WUServiceState
                $updateStatus = Get-UpdateStatus
                Show-UpdateReport -OSInfo $osInfo -Authority $authority -Policies $policies -ServiceState $serviceState -UpdateStatus $updateStatus
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

Write-Host ""
Write-Host "  Collecting Windows Update configuration..." -ForegroundColor Cyan

$osInfo       = Get-OSInfo
$authority    = Get-ManagementAuthority
$policies     = Get-UpdatePolicies
$serviceState = Get-WUServiceState
$updateStatus = Get-UpdateStatus

Show-UpdateReport -OSInfo $osInfo -Authority $authority -Policies $policies -ServiceState $serviceState -UpdateStatus $updateStatus

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
