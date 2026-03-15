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

### ProactiveRemediation/WUDUP-Detect.ps1 (~230 lines) — Intune Proactive Remediation Detection
- Non-interactive, runs as SYSTEM
- Uses `Write-Output` (not `Write-Host`) for Intune to capture
- Exit 0 = WUfB compliant, Exit 1 = non-compliant (triggers remediation)
- Purpose: discover if WUfB is managing the device, not configure it

### ProactiveRemediation/WUDUP-Remediate.ps1 (~200 lines) — Intune Proactive Remediation
- Non-interactive, runs as SYSTEM
- Only removes blockers (WSUS config, stale pauses) and sets PolicyDrivenSource keys
- Does NOT set update policies (deferrals, deadlines, version pins) — those come from Intune Update Rings
- Includes SCCM co-management guard (CoManagementFlags bit 16)
- Exit 0 = success, Exit 1 = failure

## Architecture — Cross-Script Consistency

**Critical rule: All three scripts must use the same WUfB detection logic, cleanup lists, and remediation approaches.** When modifying any detection check, blocker, indicator, cleanup value, or remediation behavior — update ALL three scripts together and verify consistency before committing.

### Blockers (checked in Detect, removed by Remediate)
- `NoAutoUpdate=1` in AU subkey — disables all updates, non-compliant regardless of WUfB indicators

### Shared WUfB Indicators (checked in Detect, checked in WUDUP Get-ManagementAuthority, displayed by WUDUP)
- `SetPolicyDrivenUpdateSourceFor{Feature,Quality,Driver,Other}Updates` (value 0 = WU) — most definitive signal, requires `UseUpdateClassPolicySource=1` in AU subkey for direct registry writes
- `DeferFeatureUpdatesPeriodInDays`, `DeferQualityUpdatesPeriodInDays` (max 365 / 30 respectively)
- `TargetReleaseVersion` + `TargetReleaseVersionInfo` + `ProductVersion` — requires BOTH `TargetReleaseVersion=1` AND `TargetReleaseVersionInfo` non-null to count as indicator
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
- **Split-source**: WSUS configured + PolicyDrivenSource=0 for some update types. This IS valid WUfB, not a misconfiguration.
- **Dual-scan**: WSUS + WUfB deferrals WITHOUT PolicyDrivenSource override AND `DisableDualScan` not set. This IS a misconfiguration to flag.
- **Stale MDM**: PolicyManager keys exist but no active enrollment in `HKLM:\SOFTWARE\Microsoft\Enrollments`.
- **UseUpdateClassPolicySource**: Must be set to 1 in AU subkey when writing PolicyDrivenSource keys via direct registry write (not GPO/CSP). GPO and CSP set this automatically.

### Cleanup Lists (must stay complete)
- **WSUS cleanup** (when switching to WUfB): `WUServer`, `WUStatusServer`, `UpdateServiceUrlAlternate`, `DoNotConnectToWindowsUpdateInternetLocations`, `SetDisableUXWUAccess`, `UseWUServer`
- **AU blockers**: `NoAutoUpdate=1` — must be removed for WUfB to function
- **Pause cleanup**: timestamps (`PauseFeature/QualityUpdatesStartTime/EndTime`) AND enable flags (`PauseFeatureUpdates`, `PauseQualityUpdates`)
- **WUfB cleanup** (when switching to WSUS): all WUfB indicator values (including both `Configure*` and `Compliance*` deadline names, version targeting keys) + `UseUpdateClassPolicySource`

### Post-Switch Actions (must be consistent)
- `usoclient StartScan` — triggered after source switching in both WUDUP.ps1 and WUDUP-Remediate.ps1
- `NoAutoUpdate` removal — both scripts remove it (not set to 0) when switching to WUfB

### COM Objects
- `Microsoft.Update.SystemInfo` — authoritative pending reboot check (matches Settings app). Registry flags (`RebootRequired`, CBS `RebootPending`) are supplemental/often stale.

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

## Development Notes

- **PowerShell 5.1 compatible** — no PS 7+ only syntax. All scripts start with `#Requires -Version 5.1`.
- **No external dependencies** — pure registry reads, `Get-Service`, `Get-CimInstance`, COM objects. No modules to install.
- **No test framework** — manual testing on Windows. Verify on both PS 5.1 and PS 7+.
- **Delivery Optimization GP value name** is `DownloadMode` (not `DODownloadMode`, which is the CSP name).
- **Quality deferral max is 30 days** (not 35 — that's the pause max).
- **Compliance deadline naming**: GP and MDM use different registry value names for the same policies. Detection must check both. See the WUfB Indicators section above.
- **Known empirical test needed**: When writing compliance deadlines directly to the GP registry path, it's unclear whether the WU client reads `Configure*` or `Compliance*` names. Detection handles both; writes currently use `Configure*` names.
