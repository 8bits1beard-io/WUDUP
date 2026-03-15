# WUDUP

**Windows Update Dashboard: Unified Provisioning**

A PowerShell toolkit for auditing, diagnosing, and managing Windows Update configuration on Windows 10/11 devices. WUDUP detects your device's update management authority, reads all relevant policies, and displays a color-coded dashboard — or outputs structured data for fleet-scale automation.

Includes an Intune Proactive Remediation pair for ensuring devices are managed by Windows Update for Business (WUfB).

## Features

- **Management authority detection** — identifies SCCM (with co-management workload check), MDM/Intune (with enrollment verification), WSUS, WUfB/GPO, or local configuration
- **Comprehensive policy audit** — reads 70+ registry values across GP, MDM, UX, and internal paths
- **Update source verification** — PolicyDrivenSource keys, WSUS configuration, split-source detection, dual-scan flagging
- **Runtime service state** — WU Agent (wuauserv), Update Orchestrator (UsoSvc), registered update services via COM API
- **Pending reboot accuracy** — uses `Microsoft.Update.SystemInfo` COM API (same source as Settings app)
- **Recent update history** — last 10 updates via `Microsoft.Update.Session` COM API
- **Source switching** — switch between WUfB, WSUS, and Microsoft Update direct with automatic backup/restore
- **Non-interactive report mode** — structured output for fleet collection and automation
- **Intune Proactive Remediation** — detect + remediate script pair for WUfB compliance

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (ships with Windows)
- Administrator privileges for modifications (read-only audit works without)
- No external modules or dependencies

## Quick Start

### Interactive Dashboard

```powershell
# Run as Administrator for full functionality
.\WUDUP.ps1
```

Displays a color-coded dashboard with all Windows Update configuration. If running as admin, offers a modification menu.

### Structured Report (Automation)

```powershell
# Output structured object for automation
.\WUDUP.ps1 -Report

# Export to JSON
.\WUDUP.ps1 -Report | ConvertTo-Json -Depth 5 | Out-File report.json

# Collect across fleet via Invoke-Command
Invoke-Command -ComputerName $devices -FilePath .\WUDUP.ps1 -ArgumentList @($true)
```

The `-Report` switch suppresses all interactive output and returns a single `PSCustomObject` containing all collected data.

## Intune Proactive Remediation

The [`ProactiveRemediation/`](ProactiveRemediation/) folder contains a detect + remediate script pair for ensuring devices are managed by WUfB.

- **Detection** checks for WUfB indicators (PolicyDrivenSource, deferrals, deadlines, version targeting, etc.) and blockers (`NoAutoUpdate`, WSUS, SCCM)
- **Remediation** only removes blockers — it does not set update policies (those come from your Intune WUfB Update Ring)

See the [ProactiveRemediation README](ProactiveRemediation/README.md) for full detection logic, remediation actions, and deployment instructions.

## Dashboard Sections

| Section | What It Shows |
|---------|---------------|
| OS Information | Build, version, edition, architecture |
| Management Authority | Who manages updates (SCCM/Intune/WSUS/GPO/Local), co-management state |
| Windows Update Service | wuauserv + UsoSvc status and startup type |
| Update Status | Pending reboot (COM API), last install/scan time |
| OS Version Pinning | TargetReleaseVersion, ProductVersion |
| Update Source | WSUS server, UseWUServer, BlockInternetWU, dual-scan detection |
| Policy-Driven Update Source | Per-type source (Feature/Quality/Driver/Other) — shown only when configured |
| Deferral Policies | Feature/quality deferral days and source |
| Compliance Deadlines | Feature/quality deadlines and grace periods — shown only when configured |
| Channel / Preview Builds | BranchReadinessLevel, ManagePreviewBuilds — shown only when configured |
| Auto-Update Behavior | AUOptions, scheduled install, always reboot, SetDisableUXWUAccess |
| Pause Status | Feature/quality pause with expiry |
| Active Hours | Policy-enforced or user-set, smart active hours |
| Delivery Optimization | Download mode and source |
| Recent Update History | Last 10 updates with result status — shown only when history available |
| Registered Update Services | Runtime WU agent services via COM API — shown only when services registered |

## Modification Menu (Admin Only)

When running as Administrator, WUDUP offers an interactive menu:

- **[1]** Set OS version pin
- **[2]** Remove OS version pin
- **[3]** Set deferral periods
- **[4]** Configure auto-update behavior
- **[5]** Set active hours
- **[6]** Pause updates
- **[7]** Unpause updates
- **[S]** Switch update source (WUfB / WSUS / Direct)
- **[B]** Backup current settings
- **[R]** Restore settings from backup
- **[8]** Refresh report
- **[0]** Exit

Source switching automatically backs up current settings before making changes. Backups are stored as JSON at `%ProgramData%\WUDUP\Backups\`. Backups use a typed format (v2) that records the registry value type (DWord, String, ExpandString, Binary, etc.) alongside each value so it is restored with the correct type. The MDM PolicyManager path is included in backups; if the device has an active Intune enrollment, MDM values will be re-delivered on the next sync and will overwrite any restored values.

## Data Sources

WUDUP reads from 12 registry base paths, 3 Windows services, 3 COM objects, and 1 WMI class. See [`SOURCES.md`](SOURCES.md) for the complete reference with every registry value name, type, and description.

## Key Concepts

**Split-source** — WSUS configured but `SetPolicyDrivenUpdateSourceFor*=0` directs some update types to Windows Update. This is a valid WUfB configuration.

**Dual-scan** — WSUS active with WUfB deferral policies but no PolicyDrivenSource override. This is a misconfiguration where the WU client may scan both WSUS and Microsoft Update unpredictably.

**Stale MDM** — PolicyManager registry keys exist but no active enrollment in `HKLM:\SOFTWARE\Microsoft\Enrollments`. Indicates a device was previously MDM-managed but enrollment was removed.

**UseUpdateClassPolicySource** — Must be set to `1` in the AU registry subkey when writing PolicyDrivenSource keys via direct registry writes. GPO and CSP set this automatically; direct writes do not.

## License

This project is provided as-is for IT administration purposes.
