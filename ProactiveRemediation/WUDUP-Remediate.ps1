#Requires -Version 5.1
<#
.SYNOPSIS
    WUDUP Remediation Script - Removes blockers so WUfB policy can take effect.

.DESCRIPTION
    Intune Proactive Remediation script. Runs when WUDUP-Detect.ps1 reports
    non-compliant (device not managed by WUfB).

    This script only removes configuration that blocks WUfB from managing the
    device. It does NOT set update policies (deferrals, deadlines, version pins,
    etc.) — those should come from your Intune WUfB Update Ring assignment.

    Actions:
    1. Checks for SCCM — warns and exits if WU workload is not shifted
    2. Stops WU-related services (wuauserv, bits, usosvc) to prevent cached state
    3. Removes WSUS configuration (WUServer, WUStatusServer, UseWUServer, etc.)
    4. Sets PolicyDrivenUpdateSource keys to direct all updates to Windows Update
    5. Removes NoAutoUpdate and AUOptions=1 if set (re-enables automatic updates)
    6. Cleans stale pause entries
    7. Clears WU client internal policy cache (UpdatePolicy)
    8. Clears SoftwareDistribution folder (forces fresh scan state)
    9. Re-enables Windows Update (wuauserv) and Update Orchestrator (UsoSvc) services if disabled
    10. Starts services and triggers Intune re-sync + WU scan

    Exit 0 = Remediation succeeded
    Exit 1 = Remediation failed

.NOTES
    Author:  Joshua Walderbach
    Tool:    WUDUP Remediation v2.0.0
    Created: 12 March 2026
    Context: Runs as SYSTEM via Intune Proactive Remediations
#>

# ============================================================================
#  CONFIGURATION
# ============================================================================

# SCCM behavior: set to $true to allow remediation even on SCCM-managed devices
$Config_AllowOnSCCM = $false   # $false = skip remediation if SCCM manages WU workload

# ============================================================================
#  REGISTRY PATHS
# ============================================================================

$RegPath_WU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$RegPath_AU = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

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
$script:ColorReset = if ($script:UseColor) { "$ESC[0m" }  else { '' }
$script:ColorPass  = if ($script:UseColor) { "$ESC[32m" } else { '' }  # green
$script:ColorFail  = if ($script:UseColor) { "$ESC[31m" } else { '' }  # red
$script:ColorSkip  = if ($script:UseColor) { "$ESC[33m" } else { '' }  # yellow
$script:ColorBold  = if ($script:UseColor) { "$ESC[1m" }  else { '' }

function Colorize-Result {
    param([string]$Result)
    $c = switch ($Result) {
        'REMEDIATED' { $script:ColorPass }
        'SKIPPED'    { $script:ColorSkip }
        'ERROR'      { $script:ColorFail }
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

$script:LogFilePath = Join-Path $env:ProgramData 'WUDUP\Logs\remediate.log'

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

# Writes the FULL verbose remediation report to the log file with a clean separator.
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
    $lines += "$(Colorize-Result $Result)"
    $lines += ""
    $lines += "Reason: $Reason"
    if ($Changes -and $Changes.Count -gt 0) {
        $lines += ""
        $lines += "Actions:"
        foreach ($c in $Changes) { $lines += $c }
    }
    return ($lines -join "`n")
}

# Compact output for Intune Proactive Remediation portal display.
# Verdict on line 1, any WARNING notes (things that couldn't be auto-fixed)
# on subsequent lines. Full verbose report is always written to remediate.log
# for on-device troubleshooting. Used automatically when running as SYSTEM.
function Format-CompactOutput {
    param(
        [string]$Result,           # REMEDIATED / SKIPPED / ERROR
        [string]$Reason,           # Required only for SKIPPED/ERROR
        [string[]]$Warnings        # Lines starting with WARNING that need admin attention
    )
    $lines = @()
    if ($Reason) {
        $lines += "$Result - $Reason"
    } else {
        $lines += $Result
    }

    if ($Warnings -and $Warnings.Count -gt 0) {
        foreach ($w in $Warnings) { $lines += $w }
    }

    return ($lines -join "`n")
}

# Formats a value for before/after display: $null -> <not set>, '' -> <empty>, else stringified.
function Format-Val {
    param($Value)
    if ($null -eq $Value) { return '<not set>' }
    if ($Value -is [string] -and $Value -eq '') { return '<empty>' }
    return "$Value"
}

# Builds a numbered remediation action entry showing before/after values.
function Add-Action {
    param(
        [string]$Description,
        $Before,
        $After,
        [string]$Path = $null,
        [switch]$AfterDeleted
    )
    $script:actionNum++
    $num = '{0:D2}' -f $script:actionNum
    $beforeStr = Format-Val $Before
    $afterStr  = if ($AfterDeleted) { '<deleted>' } else { Format-Val $After }
    $lines = @()
    $lines += "  [$num] $Description"
    $lines += "       Before: $beforeStr"
    $lines += "       After:  $afterStr"
    if ($Path) { $lines += "       Path:   $Path" }
    return $lines
}

# Builds a numbered note line (no before/after — for warnings or status messages).
# Notes starting with "WARNING" are also tracked separately for the compact output.
function Add-Note {
    param([string]$Message)
    $script:actionNum++
    $num = '{0:D2}' -f $script:actionNum
    if ($Message -like 'WARNING*') {
        $script:Warnings += $Message
    }
    return @("  [$num] $Message")
}

# ============================================================================
#  REMEDIATION
# ============================================================================

try {
    Write-Log "Remediation started"
    $changes = @()
    $script:actionNum = 0
    $script:Warnings = @()

    # --- Step 0: SCCM guard ---
    $sccmService = Get-Service -Name 'ccmexec' -ErrorAction SilentlyContinue
    $hasSCCM = ($null -ne $sccmService -and (Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'))

    if ($hasSCCM) {
        # Check if co-management has shifted the WU workload to Intune
        $coMgmtFlags = Get-SafeRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\CCM' -Name 'CoManagementFlags'
        $wuShiftedToIntune = ($null -ne $coMgmtFlags -and ($coMgmtFlags -band 16) -eq 16)

        if (-not $wuShiftedToIntune -and -not $Config_AllowOnSCCM) {
            $skipNotes  = Add-Note "SCCM detected (CoManagementFlags=$(Format-Val $coMgmtFlags), bit 4 NOT set)"
            $skipNotes += Add-Note 'Set $Config_AllowOnSCCM = $true to override and force remediation'
            $verboseMsg = Format-Output -Result 'SKIPPED' `
                -Reason "SCCM/ConfigMgr manages WU workload — local changes will be overwritten" `
                -Changes $skipNotes
            $compactMsg = Format-CompactOutput -Result 'SKIPPED' `
                -Reason "SCCM manages WU workload (CoManagementFlags=$(Format-Val $coMgmtFlags), bit 4 NOT set)"
            Write-LogReport -Report $verboseMsg
            if ($script:IsSystem) { Write-Output $compactMsg } else { Write-Output $verboseMsg }
            exit 1
        }

        if ($wuShiftedToIntune) {
            $changes += Add-Note "SCCM co-managed — WU workload shifted to Intune (CoManagementFlags=$coMgmtFlags)"
        }
        else {
            $changes += Add-Note 'WARNING: SCCM active, forced to continue via $Config_AllowOnSCCM = $true'
        }
    }

    # --- Step 0b: Check for MDM-delivered blockers that remediation cannot fix ---
    $mdmPath = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
    $mdmAllowAutoUpdate = Get-SafeRegistryValue -Path $mdmPath -Name 'AllowAutoUpdate'
    if ($mdmAllowAutoUpdate -eq 5) {
        $changes += Add-Note 'WARNING: MDM AllowAutoUpdate=5 detected (auto updates disabled via Intune) — review device config profiles, cannot be fixed locally'
    }
    $mdmAllowUpdateService = Get-SafeRegistryValue -Path $mdmPath -Name 'AllowUpdateService'
    if ($mdmAllowUpdateService -eq 0) {
        $changes += Add-Note 'WARNING: MDM AllowUpdateService=0 detected (all update services blocked via Intune) — review device config profiles, cannot be fixed locally'
    }

    # --- Step 1: Stop WU-related services before making changes ---
    # Prevents cached in-memory state from overriding registry changes
    $stopServices = @('wuauserv', 'bits', 'UsoSvc')
    $svcStatusBefore = @{}
    foreach ($svcName in $stopServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        $svcStatusBefore[$svcName] = if ($null -ne $svc) { "$($svc.Status)" } else { '<not found>' }
        if ($null -ne $svc -and $svc.Status -eq 'Running') {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
        }
    }
    $svcStatusAfter = @{}
    foreach ($svcName in $stopServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        $svcStatusAfter[$svcName] = if ($null -ne $svc) { "$($svc.Status)" } else { '<not found>' }
    }
    $beforeStr = ($stopServices | ForEach-Object { "$_=$($svcStatusBefore[$_])" }) -join ', '
    $afterStr  = ($stopServices | ForEach-Object { "$_=$($svcStatusAfter[$_])" }) -join ', '
    $changes += Add-Action -Description 'Stop WU-related services' -Before $beforeStr -After $afterStr

    # --- Step 2: Remove WSUS configuration ---
    $wsusValues = @(
        @{ Path = $RegPath_WU; Name = 'WUServer' },
        @{ Path = $RegPath_WU; Name = 'WUStatusServer' },
        @{ Path = $RegPath_WU; Name = 'DoNotConnectToWindowsUpdateInternetLocations' },
        @{ Path = $RegPath_WU; Name = 'SetDisableUXWUAccess' },
        @{ Path = $RegPath_WU; Name = 'DisableWindowsUpdateAccess' },
        @{ Path = $RegPath_WU; Name = 'UpdateServiceUrlAlternate' },
        @{ Path = $RegPath_AU; Name = 'UseWUServer' }
    )

    foreach ($item in $wsusValues) {
        $current = Get-SafeRegistryValue -Path $item.Path -Name $item.Name
        if ($null -ne $current) {
            Remove-RegValue -Path $item.Path -Name $item.Name
            $changes += Add-Action -Description "Remove WSUS value: $($item.Name)" `
                -Before $current -AfterDeleted -Path "$($item.Path)\$($item.Name)"
        }
    }

    # --- Step 3: Set PolicyDrivenUpdateSource (Windows 10 2004+ / Windows 11) ---
    $sourceKeys = @(
        'SetPolicyDrivenUpdateSourceForFeatureUpdates',
        'SetPolicyDrivenUpdateSourceForQualityUpdates',
        'SetPolicyDrivenUpdateSourceForDriverUpdates',
        'SetPolicyDrivenUpdateSourceForOtherUpdates'
    )

    foreach ($key in $sourceKeys) {
        $before = Get-SafeRegistryValue -Path $RegPath_WU -Name $key
        Set-RegDWord -Path $RegPath_WU -Name $key -Value 0
        $changes += Add-Action -Description "Set $key = 0 (Windows Update)" `
            -Before $before -After 0 -Path "$RegPath_WU\$key"
    }
    # Required for PolicyDrivenSource to take effect when set via direct registry write (not GPO/CSP)
    $useClassBefore = Get-SafeRegistryValue -Path $RegPath_AU -Name 'UseUpdateClassPolicySource'
    Set-RegDWord -Path $RegPath_AU -Name 'UseUpdateClassPolicySource' -Value 1
    $changes += Add-Action -Description 'Set UseUpdateClassPolicySource = 1 (enables direct PolicyDrivenSource writes)' `
        -Before $useClassBefore -After 1 -Path "$RegPath_AU\UseUpdateClassPolicySource"

    # --- Step 4: Remove update-disabling registry values ---
    $noAutoUpdate = Get-SafeRegistryValue -Path $RegPath_AU -Name 'NoAutoUpdate'
    if ($noAutoUpdate -eq 1) {
        Remove-RegValue -Path $RegPath_AU -Name 'NoAutoUpdate'
        $changes += Add-Action -Description 'Remove NoAutoUpdate (re-enables automatic updates)' `
            -Before $noAutoUpdate -AfterDeleted -Path "$RegPath_AU\NoAutoUpdate"
    }

    $auOptions = Get-SafeRegistryValue -Path $RegPath_AU -Name 'AUOptions'
    if ($auOptions -eq 1) {
        Remove-RegValue -Path $RegPath_AU -Name 'AUOptions'
        $changes += Add-Action -Description 'Remove AUOptions (clears Never check setting)' `
            -Before $auOptions -AfterDeleted -Path "$RegPath_AU\AUOptions"
    }

    # --- Step 5: Clean up stale pause entries ---
    $pauseValues = @(
        'PauseFeatureUpdates', 'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime',
        'PauseQualityUpdates', 'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime'
    )
    foreach ($v in $pauseValues) {
        $pauseBefore = Get-SafeRegistryValue -Path $RegPath_WU -Name $v
        if ($null -ne $pauseBefore) {
            Remove-RegValue -Path $RegPath_WU -Name $v
            $changes += Add-Action -Description "Remove stale pause entry: $v" `
                -Before $pauseBefore -AfterDeleted -Path "$RegPath_WU\$v"
        }
    }

    # --- Step 6: Clear WU client internal policy cache ---
    # The UpdatePolicy path stores the WU client's resolved policy state. Stale entries
    # here cause the client to ignore registry policy changes. Intune re-sync rebuilds it.
    $updatePolicyPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy'
    if (Test-Path $updatePolicyPath) {
        Remove-Item -Path $updatePolicyPath -Recurse -Force -ErrorAction SilentlyContinue
        $changes += Add-Action -Description 'Clear WU client UpdatePolicy cache (resolved-policy state)' `
            -Before 'present' -AfterDeleted -Path $updatePolicyPath
    }

    # --- Step 7: Clear SoftwareDistribution folder ---
    # Forces a fresh scan state and rebuilds the WU client database. Services must be
    # stopped first (Step 1) or files will be locked.
    $sdPath = "$env:SystemRoot\SoftwareDistribution"
    if (Test-Path $sdPath) {
        Remove-Item -Path $sdPath -Recurse -Force -ErrorAction SilentlyContinue
        $changes += Add-Action -Description 'Clear SoftwareDistribution folder (forces fresh WU scan database)' `
            -Before 'present' -AfterDeleted -Path $sdPath
    }

    # --- Step 8: Re-enable Windows Update services if disabled ---
    $svcNames = @('wuauserv', 'UsoSvc')
    foreach ($svcName in $svcNames) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($null -ne $svc -and $svc.StartType -eq 'Disabled') {
            Set-Service -Name $svcName -StartupType Manual -ErrorAction SilentlyContinue
            $changes += Add-Action -Description "Re-enable $svcName service startup type" `
                -Before 'Disabled' -After 'Manual' `
                -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName\Start"
        }
    }

    # --- Step 9: Start services and trigger policy re-sync ---
    # Start services back up so they read fresh registry state
    foreach ($svcName in $stopServices) {
        Start-Service -Name $svcName -ErrorAction SilentlyContinue
    }
    $svcStatusFinal = @{}
    foreach ($svcName in $stopServices) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        $svcStatusFinal[$svcName] = if ($null -ne $svc) { "$($svc.Status)" } else { '<not found>' }
    }
    $startBefore = ($stopServices | ForEach-Object { "$_=$($svcStatusAfter[$_])" }) -join ', '
    $startAfter  = ($stopServices | ForEach-Object { "$_=$($svcStatusFinal[$_])" }) -join ', '
    $changes += Add-Action -Description 'Start WU-related services' -Before $startBefore -After $startAfter

    # Trigger Intune to re-deliver policies (rebuilds PolicyManager entries)
    $pushTask = Get-ScheduledTask -TaskName 'PushLaunch' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $pushTask) {
        Start-ScheduledTask -TaskName $pushTask.TaskName -TaskPath $pushTask.TaskPath -ErrorAction SilentlyContinue
        $changes += Add-Action -Description 'Trigger Intune policy re-sync (PushLaunch scheduled task)' `
            -Before 'not triggered' -After 'triggered' `
            -Path "$($pushTask.TaskPath)$($pushTask.TaskName)"
    }
    else {
        $changes += Add-Note 'PushLaunch scheduled task not found — Intune re-sync skipped'
    }

    # Trigger WU scan via usoclient
    try {
        Start-Process -FilePath 'usoclient' -ArgumentList 'StartScan' -NoNewWindow -Wait -ErrorAction Stop
        $changes += Add-Action -Description 'Trigger Windows Update scan (usoclient StartScan)' `
            -Before 'not triggered' -After 'triggered'
    }
    catch {
        $changes += Add-Note 'WU scan trigger skipped (usoclient unavailable)'
    }

    # --- Done ---
    $verboseMsg = Format-Output -Result 'REMEDIATED' `
        -Reason "Blockers removed, WU state reset — device ready for WUfB policy" `
        -Changes $changes
    $compactMsg = Format-CompactOutput -Result 'REMEDIATED' `
        -Warnings $script:Warnings
    Write-LogReport -Report $verboseMsg
    if ($script:IsSystem) { Write-Output $compactMsg } else { Write-Output $verboseMsg }
    exit 0
}
catch {
    $errMsg = "ERROR - Remediation failed: $($_.Exception.Message)"
    Write-Log $errMsg
    Write-Output $errMsg
    exit 1
}
