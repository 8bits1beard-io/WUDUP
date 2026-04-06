# WUDUP Proactive Remediation

> Find Windows devices that Intune thinks it's managing — but isn't — and fix them automatically.

A pair of Intune Proactive Remediation scripts that verify a Windows device's update infrastructure is correctly set up for **Windows Update for Business (WUfB)**, and remove the blockers that silently take devices out of policy: leftover WSUS pointers, disabled services, stale GPO settings, dual-scan misconfigurations, missing `PolicyDrivenUpdateSource` keys, and more.

The detection script answers a single question: **"Does this device have all the necessary settings so that Intune WUfB can manage all updates?"** The remediation script removes anything that says no.

- `WUDUP-Detect.ps1` — exit `0` = compliant, exit `1` = non-compliant (triggers remediation)
- `WUDUP-Remediate.ps1` — removes blockers, resets WU client state, re-syncs Intune

Both scripts run as SYSTEM, are non-interactive, and produce a numbered, structured report that tells you exactly which check failed, what the current value is, and what it should be.

---

## Example output

Both scripts emit two different output formats depending on context:

- **Run by Intune as SYSTEM** → a *compact* summary that fits in the Intune Output column without truncation. Shows the result, only the failed checks (one per line, with the check number for cross-reference), a one-line health summary, and a pointer to the full log file on the device.
- **Run interactively for testing** → the full verbose report with all 18 checks, current/expected values, registry paths, issues, remediation guidance, health summary, and policy indicators. ANSI color is also enabled (green PASS, red FAIL, yellow SKIP).
- **Always** → the full verbose report is appended to `%ProgramData%\WUDUP\Logs\detect.log` (or `remediate.log`) on the device, regardless of which output format went to stdout. So you get the clean Intune view AND the complete forensic detail on the device.

### What Intune sees (compact, ~500 bytes)

```
NON-COMPLIANT - 6 issues found

[11] SetPolicyDrivenUpdateSourceForFeatureUpdates: GP=<not set>, MDM=<not set>
[12] SetPolicyDrivenUpdateSourceForQualityUpdates: GP=<not set>, MDM=<not set>
[13] SetPolicyDrivenUpdateSourceForDriverUpdates: GP=<not set>, MDM=<not set>
[14] SetPolicyDrivenUpdateSourceForOtherUpdates: GP=<not set>, MDM=<not set>
[16] Intune Update Ring delivery: Not detected
[17] MDM enrollment health: Not enrolled (no enrollment with EnrollmentState=1)

Health: Ring=None | MDM=None | Scan=2d | Reboot=No
Full report: C:\ProgramData\WUDUP\Logs\detect.log
```

### What you see when testing locally (verbose)

```
=== WUDUP Detection ===
NON-COMPLIANT — 6 issues found — device is not WUfB compliant

Checks Performed:
  [01] [PASS] NoAutoUpdate (1 = automatic updates disabled)
         Current:  <not set>
         Expected: <not set> or 0
         Path:     HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate
  [08] [PASS] wuauserv service startup type
         Current:  Manual
         Expected: Manual or Automatic (not Disabled)
         Path:     HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv\Start
  [11] [FAIL] SetPolicyDrivenUpdateSourceForFeatureUpdates
         Current:  GP=<not set>, MDM=<not set>
         Expected: 0 (Windows Update) on GP path OR MDM path
         Path:     GP: HKLM:\...\WindowsUpdate  |  MDM: HKLM:\...\PolicyManager\current\device\Update
  [16] [FAIL] Intune Update Ring delivery
         Current:  Not detected
         Expected: Active — WUfB values delivered via PolicyManager Providers path
         Path:     HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\<GUID>\default\device\Update
  ... 18 checks total ...

Issues Found:
  Feature updates: PolicyDrivenSource not configured (missing)
  Quality updates: PolicyDrivenSource not configured (missing)
  Driver updates:  PolicyDrivenSource not configured (missing)
  Other updates:   PolicyDrivenSource not configured (missing)
  No Intune WUfB Update Ring is actively delivering policy to this device
  No active Intune MDM enrollment — device cannot receive WUfB policy

Remediation:
  Set all 4 PolicyDrivenSource keys to 0 (remediation script handles this automatically)
  Assign a WUfB Update Ring to this device in Intune
  Re-enroll this device in Intune (manual action required)

Management Channel:
  Update Ring:    Not detected
  MDM:            Not enrolled
  Last WU scan:   2 days ago
  Last install:   2026-04-04 16:32
  Pending reboot: No
```

The remediation script follows the same dual-output pattern. Intune sees a one-line summary plus any warnings:

```
REMEDIATED - Blockers removed, WU state reset
Actions performed: 12 (see log for before/after detail)
Full report: C:\ProgramData\WUDUP\Logs\remediate.log
```

The local log gets the full numbered action list with before/after values for every change:

```
=== WUDUP Remediation ===
REMEDIATED

Reason: Blockers removed, WU state reset — device ready for WUfB policy

Actions:
  [01] Stop WU-related services
       Before: wuauserv=Running, bits=Running, UsoSvc=Running
       After:  wuauserv=Stopped, bits=Stopped, UsoSvc=Stopped
  [02] Remove WSUS value: WUServer
       Before: http://wsus.example.com:8530
       After:  <deleted>
       Path:   HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\WUServer
  [05] Set SetPolicyDrivenUpdateSourceForFeatureUpdates = 0 (Windows Update)
       Before: <not set>
       After:  0
       Path:   HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\SetPolicyDrivenUpdateSourceForFeatureUpdates
  ...
```

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later (no modules required — pure registry, services, and COM)
- Microsoft Intune subscription with the **Endpoint analytics > Remediations** (Proactive Remediations) feature
- Devices enrolled in Intune (or co-managed via SCCM with the Windows Update workload shifted to Intune)
- Local admin / SYSTEM context for the remediation script to make changes

---

## Quick start

1. **Download** `WUDUP-Detect.ps1` and `WUDUP-Remediate.ps1` from this folder.
2. In the Intune admin center, go to **Devices → Remediations** (or **Endpoint analytics → Proactive remediations**).
3. **Create script package**:
   - Detection script file → `WUDUP-Detect.ps1`
   - Remediation script file → `WUDUP-Remediate.ps1`
   - **Run this script using the logged-on credentials** → **No** (must run as SYSTEM)
   - **Enforce script signature check** → No (or sign the scripts yourself)
   - **Run script in 64-bit PowerShell** → Yes
4. **Assign** to your target device groups and pick a schedule (daily is typical).
5. After the next check-in, review the **Device status** view — the structured report appears under **Pre-remediation detection output** and **Post-remediation detection output**.

You can also run either script locally for testing:

```powershell
# As admin, in an elevated PowerShell session
.\WUDUP-Detect.ps1
.\WUDUP-Remediate.ps1
```

Local runs produce the same output but with ANSI color highlighting.

---

## Configuration

All configuration flags live at the top of each script — edit them before uploading to Intune.

### `WUDUP-Detect.ps1`

| Flag | Default | Effect |
|------|---------|--------|
| `$Config_RequireUpdateRing` | `$true` | Require an Intune Update Ring to be actively delivering WUfB policy. Set to `$false` if you only want to verify the device *can* receive policy (don't enforce that it currently *is*). |
| `$Config_RequireMDMEnrollment` | `$true` | Require an active MDM enrollment (`EnrollmentState=1`). Set to `$false` if devices may receive WUfB policy via GPO instead of Intune. |
| `$Config_MaxScanAgeDays` | `7` | Flag non-compliant if the WU client hasn't scanned within this many days. Set to `0` to disable the check. |

### `WUDUP-Remediate.ps1`

| Flag | Default | Effect |
|------|---------|--------|
| `$Config_AllowOnSCCM` | `$false` | If `$true`, the remediation script will run even on SCCM-managed devices. Default is to skip those devices since SCCM will overwrite the local changes. Co-managed devices with the WU workload shifted to Intune (`CoManagementFlags` bit 4) are remediated regardless. |

---

## How it works (in 30 seconds)

The detection script runs **18 numbered checks** and collects every issue into a single list before deciding compliance. There's no short-circuit — a non-compliant device's report shows you the *complete* picture in one Intune run, not just the first thing that failed.

The checks fall into four buckets:

1. **Update blockers (10 checks)** — registry values and service states that prevent WU from running at all (`NoAutoUpdate`, `AUOptions=1`, `DoNotConnectToWindowsUpdateInternetLocations`, `DisableWindowsUpdateAccess`, MDM `AllowAutoUpdate=5`, MDM `AllowUpdateService=0`, `wuauserv`/`UsoSvc` disabled, orphaned WSUS pointer, etc.)
2. **SCCM check** — fails if SCCM is present and the WU workload hasn't been shifted to Intune via co-management
3. **PolicyDrivenSource (4 checks)** — all four `SetPolicyDrivenUpdateSourceFor{Feature,Quality,Driver,Other}Updates` keys must equal `0` on either the GP or MDM path. This is the **core compliance gate**.
4. **Opt-in health checks (3 checks)** — Update Ring delivery, MDM enrollment health, and WU scan freshness. Each can be disabled via the config flags.

If everything passes, exit `0` (compliant). If anything fails, exit `1` (non-compliant), Intune triggers `WUDUP-Remediate.ps1`, and the remediation script removes the blockers, resets the WU client state, and triggers an Intune re-sync + WU scan.

**For the full check list, registry paths, output format spec, and remediation step details, see [TECHNICAL.md](TECHNICAL.md).**

---

## Logging

Both scripts append to `%ProgramData%\WUDUP\Logs\`:

- `detect.log` — every detection run with timestamp and outcome
- `remediate.log` — every remediation run with timestamp and outcome

Logs persist across runs and are useful when troubleshooting devices that keep flipping between compliant and non-compliant.

---

## Related

This is the Intune Proactive Remediation component of **WUDUP** (Windows Update Dashboard: Unified Provisioning). The parent repo also contains:

- `WUDUP.ps1` — interactive PowerShell dashboard for auditing and modifying WU configuration on a single device, with backup/restore and a source-switching workflow (WUfB / WSUS / Microsoft Update direct)

The PR scripts and `WUDUP.ps1` share detection logic, blocker lists, and remediation approaches — see `CLAUDE.md` in the repo root for the cross-script consistency rules.
