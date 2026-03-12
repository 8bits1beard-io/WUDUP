# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WUDUP (Windows Update Dashboard: Unified Provisioning) is a PowerShell-based toolkit for auditing and managing Windows Update configuration on Windows 10/11. It consists of three scripts that share detection logic and must stay aligned.

## Scripts

### WUDUP.ps1 (~2100 lines) — Interactive Dashboard + Modification Tool
- Color-coded console dashboard showing all WU configuration
- Interactive modification menu (admin only) for individual settings
- Source switching workflow (WUfB / WSUS / Microsoft Update direct)
- Backup/restore system (`%ProgramData%\WUDUP\Backups` as JSON)
- Runs interactively with `Read-Host` prompts; uses `Write-Host` for display

### WUDUP-Detect.ps1 (~180 lines) — Intune Proactive Remediation Detection
- Non-interactive, runs as SYSTEM
- Uses `Write-Output` (not `Write-Host`) for Intune to capture
- Exit 0 = WUfB compliant, Exit 1 = non-compliant (triggers remediation)
- No modification capability

### WUDUP-Remediate.ps1 (~220 lines) — Intune Proactive Remediation
- Non-interactive, runs as SYSTEM
- Configurable via `$Config_*` variables at top of script
- Applies WUfB configuration, removes WSUS, includes SCCM guard
- Exit 0 = success, Exit 1 = failure

## Architecture — Cross-Script Consistency

**Critical rule: All three scripts must use the same WUfB detection logic.** When adding or changing a WUfB indicator, update all three scripts.

### Shared WUfB Indicators (checked in Detect, set by Remediate, displayed by WUDUP)
- `SetPolicyDrivenUpdateSourceFor{Feature,Quality,Driver,Other}Updates` (value 0 = WU)
- `DeferFeatureUpdatesPeriodInDays`, `DeferQualityUpdatesPeriodInDays`
- `TargetReleaseVersion` + `TargetReleaseVersionInfo` + `ProductVersion`
- `ConfigureDeadlineFor{Feature,Quality}Updates`, `ConfigureDeadlineGracePeriod{,ForFeatureUpdates}`
- `BranchReadinessLevel`, `ManagePreviewBuilds`
- `ExcludeWUDriversInQualityUpdate`

### Shared Helper Pattern
All scripts use the same registry read function (identical logic):
- **WUDUP.ps1**: `Get-SafeRegistryValue` (with `$script:` scoped paths)
- **Detect/Remediate**: `Get-SafeRegistryValue` (plain variable paths, standalone context)

### Registry Paths (must match across scripts)
- GP policies: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` and `\AU` subkey
- MDM policies: `HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update`
- WUDUP.ps1 additionally reads: UX Settings, UpdatePolicy\Settings, Delivery Optimization, Enrollments, CBS, WU Auto Update results

### Management Authority Priority (WUDUP.ps1)
SCCM (with co-management check) → MDM/Intune (with enrollment verification) → WSUS (with split-source check) → WUfB/GPO → Local

### Key Concepts
- **Split-source**: WSUS configured + PolicyDrivenSource=0 for some update types. This IS valid WUfB, not a misconfiguration.
- **Dual-scan**: WSUS + WUfB deferrals WITHOUT PolicyDrivenSource override. This IS a misconfiguration to flag.
- **Stale MDM**: PolicyManager keys exist but no active enrollment in `HKLM:\SOFTWARE\Microsoft\Enrollments`.

## Development Notes

- **PowerShell 5.1 compatible** — no PS 7+ only syntax. All scripts start with `#Requires -Version 5.1`.
- **No external dependencies** — pure registry reads, `Get-Service`, `Get-CimInstance`. No modules to install.
- **No test framework** — manual testing on Windows. Verify on both PS 5.1 and PS 7+.
- **WSUS values to clean when switching to WUfB**: `WUServer`, `WUStatusServer`, `UseWUServer`, `DoNotConnectToWindowsUpdateInternetLocations`, `SetDisableUXWUAccess`
- **WUfB values to clean when switching to WSUS**: see `Get-WUfBCleanupItems` in WUDUP.ps1
