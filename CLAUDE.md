# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WUDUP (Windows Update Dashboard: Unified Provisioning) is a PowerShell-based toolkit for auditing and managing Windows Update configuration on Windows 10/11. It consists of three scripts that share detection logic and must stay aligned.

## Scripts

### WUDUP.ps1 (~2200 lines) — Interactive Dashboard + Modification Tool
- Color-coded console dashboard showing all WU configuration
- Interactive modification menu (admin only) for individual settings
- Source switching workflow (WUfB / WSUS / Microsoft Update direct)
- Backup/restore system (`%ProgramData%\WUDUP\Backups` as `.json` files)
- Runs interactively with `Read-Host` prompts; uses `Write-Host` for display

### WUDUP-Detect.ps1 (~190 lines) — Intune Proactive Remediation Detection
- Non-interactive, runs as SYSTEM
- Uses `Write-Output` (not `Write-Host`) for Intune to capture
- Exit 0 = WUfB compliant, Exit 1 = non-compliant (triggers remediation)
- Purpose: discover if WUfB is managing the device, not configure it

### WUDUP-Remediate.ps1 (~230 lines) — Intune Proactive Remediation
- Non-interactive, runs as SYSTEM
- Configurable via `$Config_*` variables at top of script
- Removes WSUS/stale config so the device falls under its assigned WUfB policy
- Sets baseline PolicyDrivenSource + deferrals; actual policy details come from Intune Update Rings
- Includes SCCM co-management guard (CoManagementFlags bit 16)
- Exit 0 = success, Exit 1 = failure

## Architecture — Cross-Script Consistency

**Critical rule: All three scripts must use the same WUfB detection logic.** When adding or changing a WUfB indicator, update all three scripts.

### Shared WUfB Indicators (checked in Detect, set by Remediate, displayed by WUDUP)
- `SetPolicyDrivenUpdateSourceFor{Feature,Quality,Driver,Other}Updates` (value 0 = WU) — most definitive signal, requires `UseUpdateClassPolicySource=1` in AU subkey for direct registry writes
- `DeferFeatureUpdatesPeriodInDays`, `DeferQualityUpdatesPeriodInDays` (max 365 / 30 respectively)
- `TargetReleaseVersion` + `TargetReleaseVersionInfo` + `ProductVersion`
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
- **Pause cleanup**: timestamps (`PauseFeature/QualityUpdatesStartTime/EndTime`) AND enable flags (`PauseFeatureUpdates`, `PauseQualityUpdates`)
- **WUfB cleanup** (when switching to WSUS): all WUfB indicator values + `UseUpdateClassPolicySource`

### COM Objects
- `Microsoft.Update.SystemInfo` — authoritative pending reboot check (matches Settings app). Registry flags (`RebootRequired`, CBS `RebootPending`) are supplemental/often stale.

## Development Notes

- **PowerShell 5.1 compatible** — no PS 7+ only syntax. All scripts start with `#Requires -Version 5.1`.
- **No external dependencies** — pure registry reads, `Get-Service`, `Get-CimInstance`, COM objects. No modules to install.
- **No test framework** — manual testing on Windows. Verify on both PS 5.1 and PS 7+.
- **Delivery Optimization GP value name** is `DownloadMode` (not `DODownloadMode`, which is the CSP name).
- **Quality deferral max is 30 days** (not 35 — that's the pause max).
- **Compliance deadline naming**: GP and MDM use different registry value names for the same policies. Detection must check both. See the WUfB Indicators section above.
- **Known empirical test needed**: When writing compliance deadlines directly to the GP registry path, it's unclear whether the WU client reads `Configure*` or `Compliance*` names. Detection handles both; writes currently use `Configure*` names.
