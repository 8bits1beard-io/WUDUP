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

### Detection Script (`WUDUP-Detect.ps1`)

Checks whether the device is managed by WUfB. Returns:
- **Exit 0** — WUfB compliant (device is receiving updates via WUfB)
- **Exit 1** — Non-compliant (WSUS, SCCM, no policy, or dual-scan misconfiguration)

Checks all WUfB indicators: PolicyDrivenSource keys, deferral policies, version targeting, compliance deadlines, channel settings, and driver exclusion. Handles split-source configurations (WSUS + PolicyDrivenSource override) as compliant.

### Remediation Script (`WUDUP-Remediate.ps1`)

Runs when detection reports non-compliant. Removes blockers so the device falls under its assigned WUfB policy:

1. Checks for SCCM — skips if WU workload hasn't been shifted to Intune
2. Removes WSUS configuration (WUServer, UseWUServer, etc.)
3. Sets PolicyDrivenSource keys to direct all update types to Windows Update
4. Sets `UseUpdateClassPolicySource=1` (required for direct registry writes)
5. Cleans stale pause entries
6. Triggers `usoclient StartScan` for immediate policy pickup

The script intentionally does **not** set update policies (deferrals, deadlines, version pins, etc.). Those should come from your Intune WUfB Update Ring assignment, which will apply automatically once the blockers are removed.

### Configuration

```powershell
$Config_AllowOnSCCM = $false   # $true to force remediation on SCCM-managed devices
```

### Deployment in Intune

1. Navigate to **Devices > Remediations** (or **Proactive remediations**)
2. Create a new remediation script package
3. Upload `WUDUP-Detect.ps1` as the detection script
4. Upload `WUDUP-Remediate.ps1` as the remediation script
5. Set **Run this script using the logged-on credentials** to **No** (runs as SYSTEM)
6. Assign to your target device groups

### Logging

Both scripts log to `%ProgramData%\WUDUP\Logs\`:
- `detect.log` — detection results with timestamps
- `remediate.log` — remediation actions with timestamps

Logs are append-only and persist across runs for troubleshooting.

## Dashboard Sections

| Section | What It Shows |
|---------|---------------|
| OS Information | Build, version, edition, architecture |
| Management Authority | Who manages updates (SCCM/Intune/WSUS/GPO/Local), co-management state |
| Windows Update Service | wuauserv + UsoSvc status and startup type |
| Update Status | Pending reboot (COM API), last install/scan time |
| Recent Update History | Last 10 updates with result status |
| OS Version Pinning | TargetReleaseVersion, ProductVersion |
| Update Source | WSUS server, UseWUServer, dual-scan detection |
| Policy-Driven Update Source | Per-type source (Feature/Quality/Driver/Other) |
| Registered Update Services | Runtime WU agent services via COM API |
| Deferral Policies | Feature/quality deferral days and source |
| Compliance Deadlines | Feature/quality deadlines and grace periods |
| Channel / Preview Builds | BranchReadinessLevel, ManagePreviewBuilds |
| Auto-Update Behavior | AUOptions, scheduled install, always reboot |
| Pause State | Feature/quality pause with expiry |
| Active Hours | Policy-enforced or user-set, smart active hours |
| Delivery Optimization | Download mode and source |
| Update UI Access | SetDisableUXWUAccess, BlockInternetWU |

## Modification Menu (Admin Only)

When running as Administrator, WUDUP offers an interactive menu:

- **[1]** Set OS version pin
- **[2]** Set deferral periods
- **[3]** Set auto-update behavior
- **[4]** Set active hours
- **[5]** Pause/unpause updates
- **[S]** Switch update source (WUfB / WSUS / Microsoft Update)
- **[B]** Backup current settings
- **[R]** Restore from backup

Source switching automatically backs up current settings before making changes. Backups are stored as JSON at `%ProgramData%\WUDUP\Backups\`.

## Data Sources

WUDUP reads from 12 registry base paths, 3 Windows services, 3 COM objects, and 1 WMI class. See [`SOURCES.md`](SOURCES.md) for the complete reference with every registry value name, type, and description.

## Key Concepts

**Split-source** — WSUS configured but `SetPolicyDrivenUpdateSourceFor*=0` directs some update types to Windows Update. This is a valid WUfB configuration.

**Dual-scan** — WSUS active with WUfB deferral policies but no PolicyDrivenSource override. This is a misconfiguration where the WU client may scan both WSUS and Microsoft Update unpredictably.

**Stale MDM** — PolicyManager registry keys exist but no active enrollment in `HKLM:\SOFTWARE\Microsoft\Enrollments`. Indicates a device was previously MDM-managed but enrollment was removed.

**UseUpdateClassPolicySource** — Must be set to `1` in the AU registry subkey when writing PolicyDrivenSource keys via direct registry writes. GPO and CSP set this automatically; direct writes do not.

## License

This project is provided as-is for IT administration purposes.
