# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WUDUP (Windows Update Dashboard: Unified Provisioning) is a PowerShell-based toolkit for auditing and managing Windows Update configuration on Windows 10/11. It consists of three scripts that share detection logic and must stay aligned.

## Scripts

### WUDUP.ps1 (~2370 lines) — Interactive Dashboard + Modification Tool
- Color-coded console dashboard showing all WU configuration
- Interactive modification menu (admin only) for individual settings
- Source switching workflow (WUfB / WSUS / Microsoft Update direct)
- Backup/restore system (`%ProgramData%\WUDUP\Backups` as `.json` files)
- Runs interactively with `Read-Host` prompts; uses `Write-Host` for display

### ProactiveRemediation/WUDUP-Detect.ps1 (~450 lines) — Intune Proactive Remediation Detection
- Non-interactive, runs as SYSTEM
- Uses `Write-Output` (not `Write-Host`) for Intune to capture
- Exit 0 = WUfB compliant, Exit 1 = non-compliant (triggers remediation)
- Purpose: discover if WUfB is managing the device, not configure it
- Checks 6 blocker conditions, collects WUfB indicators, validates management channel health
- Opt-in config flags: `$Config_RequireUpdateRing`, `$Config_RequireMDMEnrollment`, `$Config_MaxScanAgeDays`

### ProactiveRemediation/WUDUP-Remediate.ps1 (~250 lines) — Intune Proactive Remediation
- Non-interactive, runs as SYSTEM
- Stops WU services before changes, restarts after — prevents cached state from persisting
- Removes blockers (WSUS config, stale pauses, disabled services) and sets PolicyDrivenSource keys
- Clears WU client internal caches (UpdatePolicy, SoftwareDistribution) to force fresh state
- Triggers Intune policy re-sync (PushLaunch) + WU scan after changes
- Does NOT set update policies (deferrals, deadlines, version pins) — those come from Intune Update Rings
- Includes SCCM co-management guard (CoManagementFlags value 16 (bit position 4))
- Exit 0 = success, Exit 1 = failure

## Architecture — Cross-Script Consistency

**Critical rule: All three scripts must use the same WUfB detection logic, cleanup lists, and remediation approaches.** When modifying any detection check, blocker, indicator, cleanup value, or remediation behavior — update ALL three scripts together and verify consistency before committing.

### Blockers (checked in Detect and WUDUP Get-ManagementAuthority, removed by Remediate and WUDUP Switch-To functions)
All blockers must be checked consistently across all three scripts:
- `NoAutoUpdate=1` in AU subkey — disables all automatic updates
- `AUOptions=1` in AU subkey — "Never check for updates", effectively disables WU
- `DoNotConnectToWindowsUpdateInternetLocations=1` in WU key — blocks WU server connectivity
- `SetDisableUXWUAccess=1` in WU key — hides WU UI and can block update flows
- `DisableWindowsUpdateAccess=1` in WU key — turns off access to all WU features (Microsoft Autopatch conflict check)
- `wuauserv` service startup type `Disabled` — Windows Update service won't run
- `UsoSvc` service startup type `Disabled` — Update Orchestrator service won't run
- `UseWUServer=1` without a valid `WUServer` — orphaned WSUS pointer, WU client cannot reach any update server
- `AllowAutoUpdate=5` in MDM path — disables automatic updates via Intune/MDM policy (cannot be auto-remediated)
- `AllowUpdateService=0` in MDM path — blocks device from using any update service via Intune/MDM (cannot be auto-remediated)

### Shared WUfB Indicators (checked in Detect, checked in WUDUP Get-ManagementAuthority, displayed by WUDUP)
- `SetPolicyDrivenUpdateSourceFor{Feature,Quality,Driver,Other}Updates` (value 0 = WU) — most definitive signal, requires `UseUpdateClassPolicySource=1` in AU subkey for direct registry writes
- `DeferFeatureUpdatesPeriodInDays`, `DeferQualityUpdatesPeriodInDays` (max 365 / 30 respectively). GP also has separate enable flags `DeferFeatureUpdates` and `DeferQualityUpdates` — if the enable flag is 0 but a period is set, the deferral may not be active.
- `TargetReleaseVersion` + `TargetReleaseVersionInfo` + `ProductVersion` — GP stores `TargetReleaseVersion` as a DWORD enable flag (`1`/`0`) with `TargetReleaseVersionInfo` as the version string. MDM stores `TargetReleaseVersion` as the version string itself (e.g. `"24H2"`). Detection must handle both formats. WUDUP normalizes MDM-style to `TargetReleaseVersion=1` + `TargetReleaseVersionInfo="24H2"` in Get-UpdatePolicies.
- Compliance deadlines: GP writes `ComplianceDeadlineForFU` / `ComplianceDeadline` / `ComplianceGracePeriod` / `ComplianceGracePeriodForFU`; MDM uses `ConfigureDeadlineFor{Feature,Quality}Updates` / `ConfigureDeadlineGracePeriod{,ForFeatureUpdates}` — detection must check both naming conventions
- `BranchReadinessLevel` (legacy on Windows 11), `ManagePreviewBuilds`
- `ExcludeWUDriversInQualityUpdate`

### Shared Helper Pattern
All scripts use `Get-SafeRegistryValue` with identical logic:
- **WUDUP.ps1**: `$script:` scoped paths
- **Detect/Remediate**: plain variable paths, standalone context

### Registry Paths (must match across scripts)
- GP policies: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` and `\AU` subkey
- MDM policies: `HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update`
- WUDUP.ps1 additionally reads: UX Settings, UpdatePolicy\Settings, Delivery Optimization, Enrollments, CBS, WU Auto Update results
- See `SOURCES.md` for the complete registry value reference

### Management Authority Priority (WUDUP.ps1)
SCCM (with co-management check) → MDM/Intune (with enrollment verification) → WSUS (with split-source check) → WUfB/GPO → Local

### Key Concepts
- **Split-source (full)**: WSUS configured + PolicyDrivenSource=0 for ALL four update types. This IS valid WUfB — WSUS is effectively overridden.
- **Split-source (partial)**: WSUS configured + PolicyDrivenSource=0 for some types but =1 for others. This IS a misconfiguration — all update types must use WUfB. Flagged as non-compliant.
- **Dual-scan**: WSUS + WUfB deferrals WITHOUT PolicyDrivenSource override AND `DisableDualScan` not set. This IS a misconfiguration to flag.
- **Stale MDM**: PolicyManager keys exist but no active enrollment in `HKLM:\SOFTWARE\Microsoft\Enrollments`.
- **UseUpdateClassPolicySource**: Must be set to 1 in AU subkey when writing PolicyDrivenSource keys via direct registry write (not GPO/CSP). GPO and CSP set this automatically.

### Cleanup Lists (must stay complete)
- **WSUS cleanup** (when switching to WUfB): `WUServer`, `WUStatusServer`, `UpdateServiceUrlAlternate`, `DoNotConnectToWindowsUpdateInternetLocations`, `SetDisableUXWUAccess`, `DisableWindowsUpdateAccess`, `UseWUServer`
- **AU blockers**: `NoAutoUpdate=1` and `AUOptions=1` — must be removed for WUfB to function
- **Service blockers**: `wuauserv` and `UsoSvc` — re-enabled to `Manual` startup if `Disabled`
- **Pause cleanup**: timestamps (`PauseFeature/QualityUpdatesStartTime/EndTime`) AND enable flags (`PauseFeatureUpdates`, `PauseQualityUpdates`)
- **WUfB cleanup** (when switching to WSUS): all WUfB indicator values (including both `Configure*` and `Compliance*` deadline names, version targeting keys) + `UseUpdateClassPolicySource`

### Post-Switch Actions (must be consistent)
- **Service stop/start** — WUDUP-Remediate.ps1 stops `wuauserv`, `bits`, `UsoSvc` before changes and restarts after to prevent cached state. WUDUP.ps1 Switch-To functions do not stop/start (interactive context, user can restart manually).
- **UpdatePolicy cache clear** — `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy` stores the WU client's resolved policy state. WUDUP-Remediate.ps1 deletes this tree; Intune re-sync rebuilds it. Critical for fixing "Offer Ready" stalls.
- **SoftwareDistribution clear** — `%SystemRoot%\SoftwareDistribution` is the WU client's download/scan database. WUDUP-Remediate.ps1 deletes it to force fresh scan state. Services must be stopped first or files are locked.
- **Intune re-sync** — WUDUP-Remediate.ps1 triggers the `PushLaunch` scheduled task to force Intune to re-deliver policies immediately after cache clearing.
- `usoclient StartScan` — triggered after source switching in both WUDUP.ps1 and WUDUP-Remediate.ps1
- `NoAutoUpdate` and `AUOptions=1` removal — all scripts remove these (not set to 0) when switching sources
- Service re-enabling — `wuauserv` and `UsoSvc` set to `Manual` if `Disabled`, in all Switch-To functions and WUDUP-Remediate.ps1

### MDM Provider IDs (must match across scripts)
- `MS DM Server` — direct Intune enrollment
- `WMI_Bridge_SCCM_Server` — SCCM co-management bridge (Intune policies delivered through SCCM)
- Both must be recognized as valid MDM providers for Update Ring detection and enrollment health checks
- WUDUP.ps1 `Test-ActiveMDMEnrollment` accepts any non-empty ProviderID; PR detect uses a shared `$MDMProviderIDs` list

### PR Detect Configuration Flags
- `$Config_RequireUpdateRing` (`$true`) — require Intune/co-mgmt Update Ring policy delivery via PolicyManager Providers path
- `$Config_RequireMDMEnrollment` (`$true`) — require active MDM enrollment (`EnrollmentState=1`)
- `$Config_MaxScanAgeDays` (`7`) — flag non-compliant if WU client hasn't scanned in 7 days (set to 0 to disable)
- These are enforcement-only in Detect; Remediate cannot fix missing enrollments or stale scans

### COM Objects
- `Microsoft.Update.SystemInfo` — authoritative pending reboot check (matches Settings app). Registry flags (`RebootRequired`, CBS `RebootPending`) are supplemental/often stale.
- `Microsoft.Update.AutoUpdate` — primary source for scan/install timestamps via `Results.LastSearchSuccessDate` and `Results.LastInstallationSuccessDate`. More accurate than `Microsoft.Update.Session.QueryHistory` (which returns install events, not scan events). Fallback chain: AutoUpdate COM → Session.QueryHistory → legacy registry path.

## Running the Scripts

```powershell
# Interactive dashboard (read-only without admin, modification menu with admin)
.\WUDUP.ps1

# Non-interactive structured report (returns a PSCustomObject, no Write-Host output)
.\WUDUP.ps1 -Report

# Fleet collection via remoting
Invoke-Command -ComputerName $devices -FilePath .\WUDUP.ps1 -ArgumentList @($true)
```

Detect and Remediate are uploaded to Intune and run as SYSTEM — they are not meant to be run locally except for manual testing. Both log to `%ProgramData%\WUDUP\Logs\detect.log` and `remediate.log` (append-only).

### Remediate Configuration

`$Config_AllowOnSCCM = $false` (top of WUDUP-Remediate.ps1) — set to `$true` to force remediation even when SCCM is detected. Default is to skip remediation on SCCM-managed devices.

### Detect Configuration

All flags are at the top of WUDUP-Detect.ps1 and default to on for full WUfB verification:
- `$Config_RequireUpdateRing = $true` — require Intune/co-mgmt Update Ring policy delivery
- `$Config_RequireMDMEnrollment = $true` — require active MDM enrollment
- `$Config_MaxScanAgeDays = 7` — maximum days since last WU scan (0 = disabled)

## Development Notes

- **PowerShell 5.1 compatible** — no PS 7+ only syntax. All scripts start with `#Requires -Version 5.1`.
- **No external dependencies** — pure registry reads, `Get-Service`, `Get-CimInstance`, COM objects. No modules to install.
- **No test framework** — manual testing on Windows. Verify on both PS 5.1 and PS 7+.
- **Delivery Optimization GP value name** is `DownloadMode` (not `DODownloadMode`, which is the CSP name).
- **Quality deferral max is 30 days** (not 35 — that's the pause max).
- **Compliance deadline naming**: GP and MDM use different registry value names for the same policies. Detection must check both. See the WUfB Indicators section above.
- **Known empirical test needed**: When writing compliance deadlines directly to the GP registry path, it's unclear whether the WU client reads `Configure*` or `Compliance*` names. Detection handles both; writes currently use `Configure*` names.
