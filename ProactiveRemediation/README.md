# WUDUP Proactive Remediation

Intune Proactive Remediation script pair for ensuring devices are managed by Windows Update for Business (WUfB).

- **`WUDUP-Detect.ps1`** — detection script (exit 0 = compliant, exit 1 = non-compliant)
- **`WUDUP-Remediate.ps1`** — remediation script (removes blockers so WUfB policy can take effect)

Both scripts run as SYSTEM, are non-interactive, and log to `%ProgramData%\WUDUP\Logs\`.

## Detection Flow

```mermaid
flowchart TD
    Start([Detection starts]) --> Blockers{Update blockers?}

    Blockers -- Yes --> NC_Blocked[/"NON-COMPLIANT\nBlockers detected"/]
    Blockers -- No --> Collect[Collect WUfB indicators]

    Collect --> HasWSUS{WSUS configured?}

    HasWSUS -- No --> HasSCCM{SCCM detected?}
    HasWSUS -- Yes --> WSUSIndicators{WUfB indicators\npresent?}

    WSUSIndicators -- No --> NC_WSUS[/"NON-COMPLIANT\nWSUS managed"/]
    WSUSIndicators -- Yes --> PolicyDriven{PolicyDrivenSource\ndirects to WU?}

    PolicyDriven -- Yes --> HealthChecks[Management channel\nhealth checks]
    PolicyDriven -- No --> NC_Dual[/"NON-COMPLIANT\ndual-scan risk"/]

    HasSCCM -- No --> HasIndicators{WUfB indicators\npresent?}
    HasSCCM -- Yes --> CoMgmt{WU workload\nshifted to Intune?}

    CoMgmt -- No --> NC_SCCM[/"NON-COMPLIANT\nSCCM managed"/]
    CoMgmt -- Yes --> HasIndicators

    HasIndicators -- Yes --> HealthChecks
    HasIndicators -- No --> NC_None[/"NON-COMPLIANT\nno WUfB policy"/]

    HealthChecks --> UpdateRing{Update Ring\nrequired + missing?}
    UpdateRing -- Yes --> NC_Ring[/"NON-COMPLIANT\nno Update Ring"/]
    UpdateRing -- No --> MDMCheck{MDM enrollment\nrequired + missing?}
    MDMCheck -- Yes --> NC_MDM[/"NON-COMPLIANT\nno MDM enrollment"/]
    MDMCheck -- No --> ScanCheck{Scan stale\nbeyond threshold?}
    ScanCheck -- Yes --> NC_Scan[/"NON-COMPLIANT\nscan stale"/]
    ScanCheck -- No --> C_WUfB([COMPLIANT\nWUfB managed])

    style C_WUfB fill:#2d6a2d,color:#fff
    style NC_Blocked fill:#8b1a1a,color:#fff
    style NC_WSUS fill:#8b1a1a,color:#fff
    style NC_Dual fill:#8b1a1a,color:#fff
    style NC_SCCM fill:#8b1a1a,color:#fff
    style NC_None fill:#8b1a1a,color:#fff
    style NC_Ring fill:#8b1a1a,color:#fff
    style NC_MDM fill:#8b1a1a,color:#fff
    style NC_Scan fill:#8b1a1a,color:#fff
```

## Detection Details

### 1. Blocker Checks (checked first, immediate non-compliant)

| Check | Condition | Why it fails |
|-------|-----------|-------------|
| Auto-updates disabled | `NoAutoUpdate = 1` in AU subkey | Updates are disabled entirely |
| Never check | `AUOptions = 1` in AU subkey | WU client will never check for updates |
| Internet WU blocked | `DoNotConnectToWindowsUpdateInternetLocations = 1` | Device cannot reach Windows Update servers |
| WU UI disabled | `SetDisableUXWUAccess = 1` | WU access hidden/blocked |
| WU service disabled | `wuauserv` StartType = Disabled | Windows Update service won't run |
| USO service disabled | `UsoSvc` StartType = Disabled | Update Orchestrator won't run |

Any single blocker causes immediate non-compliant (exit 1).

### 2. WUfB Indicator Collection

The script collects indicators that the device is managed by WUfB. Any indicator present means WUfB may be active.

| Indicator | Registry values checked | Path priority |
|-----------|----------------------|---------------|
| Policy-driven update source | `SetPolicyDrivenUpdateSourceForFeatureUpdates` (value 0 = WU) | GP then MDM |
| | `SetPolicyDrivenUpdateSourceForQualityUpdates` (value 0 = WU) | GP then MDM |
| | `SetPolicyDrivenUpdateSourceForDriverUpdates` (value 0 = WU) | GP then MDM |
| | `SetPolicyDrivenUpdateSourceForOtherUpdates` (value 0 = WU) | GP then MDM |
| Feature deferral | `DeferFeatureUpdatesPeriodInDays` | GP then MDM |
| Quality deferral | `DeferQualityUpdatesPeriodInDays` | GP then MDM |
| Version targeting | `TargetReleaseVersion = 1` + `TargetReleaseVersionInfo` + `ProductVersion` | GP then MDM |
| Feature deadline | `ConfigureDeadlineForFeatureUpdates` at GP then MDM; fallback to `ComplianceDeadlineForFU` at GP | GP then MDM |
| Quality deadline | `ConfigureDeadlineForQualityUpdates` at GP then MDM; fallback to `ComplianceDeadline` at GP | GP then MDM |
| Grace period | `ConfigureDeadlineGracePeriod` at GP then MDM; fallback to `ComplianceGracePeriod` at GP | GP then MDM |
| Grace period (feature) | `ConfigureDeadlineGracePeriodForFeatureUpdates` at GP then MDM; fallback to `ComplianceGracePeriodForFU` at GP | GP then MDM |
| Channel targeting | `BranchReadinessLevel` | GP then MDM |
| Preview build management | `ManagePreviewBuilds` | GP then MDM |
| Driver exclusion | `ExcludeWUDriversInQualityUpdate` | GP then MDM |

### 3. Management Authority Detection

| Authority | How detected |
|-----------|-------------|
| WSUS | `UseWUServer = 1` (AU subkey) AND `WUServer` exists (WU key) |
| SCCM | `ccmexec` service running AND `HKLM:\SOFTWARE\Microsoft\CCM` exists. Co-management check: if `CoManagementFlags` value 16 (bit position 4) is set, the WU workload is considered shifted to Intune and SCCM is cleared — device evaluated for WUfB indicators instead. |

### 4. Management Channel Health Checks (opt-in)

These checks run after a device passes WUfB configuration checks. They validate whether the management channel is healthy — not just configured, but actually working.

| Check | Config flag | What it validates |
|-------|-------------|-------------------|
| Update Ring delivery | `$Config_RequireUpdateRing` | Intune/co-mgmt has delivered WUfB policy values (deferrals, deadlines, etc.) via PolicyManager Providers path |
| MDM enrollment health | `$Config_RequireMDMEnrollment` | Active MDM enrollment exists (`EnrollmentState=1` with valid ProviderID) |
| WU scan freshness | `$Config_MaxScanAgeDays` | WU client has scanned within N days |

MDM provider IDs recognized: `MS DM Server` (direct Intune) and `WMI_Bridge_SCCM_Server` (SCCM co-management bridge).

**Important**: Remediation cannot fix these conditions. If these checks fail, the output message indicates manual intervention is needed (re-enrollment, investigation, or Update Ring assignment in Intune).

### 5. Compliance Decision

| Scenario | Result | Exit |
|----------|--------|------|
| Any blocker detected | **Non-compliant** (blockers listed) | 1 |
| WUfB indicators present, no WSUS | **Compliant** | 0 |
| WUfB indicators present + WSUS, but PolicyDrivenSource directs updates to WU | **Compliant** (split-source) | 0 |
| WSUS + WUfB indicators, but no PolicyDrivenSource override | **Non-compliant** (dual-scan risk) | 1 |
| WSUS configured, no WUfB indicators | **Non-compliant** (WSUS managed) | 1 |
| SCCM detected, WU workload not shifted to Intune | **Non-compliant** (SCCM managed) | 1 |
| SCCM co-managed, WU workload shifted to Intune, but no WUfB indicators | **Non-compliant** (no WUfB policy) | 1 |
| No indicators, no WSUS, no SCCM | **Non-compliant** (no policy, default WU) | 1 |
| `$Config_RequireUpdateRing = $true` + no Update Ring detected | **Non-compliant** (no Update Ring) | 1 |
| `$Config_RequireMDMEnrollment = $true` + no active enrollment | **Non-compliant** (no MDM enrollment) | 1 |
| `$Config_MaxScanAgeDays > 0` + scan older than threshold | **Non-compliant** (scan stale) | 1 |

Compliant output always includes status tags: `[Update Ring: Active/Not detected]`, `[MDM: Enrolled via Intune/Co-mgmt bridge (UPN)/Not enrolled]`, `[LastScan: Nd ago/Unknown]`.

### Registry Paths

| Path | Purpose |
|------|---------|
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` | Group Policy WU settings |
| `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` | Group Policy Automatic Updates settings |
| `HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update` | MDM/Intune policy settings |
| `HKLM:\SOFTWARE\Microsoft\Enrollments\{GUID}` | MDM enrollment state |
| `HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\{GUID}\default\device\Update` | Per-provider MDM policy delivery |
| `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect` | Last WU scan timestamp |

## Remediation Actions

The remediation script **only removes blockers** — it does not set update policies (deferrals, deadlines, version pins, etc.). Those should come from your Intune WUfB Update Ring assignment.

| Step | Action | Details |
|------|--------|---------|
| 0 | SCCM guard | Skips if SCCM manages WU workload and co-management hasn't shifted it to Intune (`CoManagementFlags` value 16, bit position 4) |
| 1 | Remove WSUS config | `WUServer`, `WUStatusServer`, `DoNotConnectToWindowsUpdateInternetLocations`, `SetDisableUXWUAccess`, `UpdateServiceUrlAlternate`, `UseWUServer` |
| 2 | Set PolicyDrivenSource | All 4 update types set to 0 (Windows Update) + `UseUpdateClassPolicySource = 1` |
| 3 | Remove update-disabling values | `NoAutoUpdate = 1` and `AUOptions = 1` removed if set |
| 4 | Clean stale pauses | `PauseFeatureUpdates`, `PauseQualityUpdates` + their start/end timestamps |
| 5 | Re-enable WU services | `wuauserv` and `UsoSvc` set to `Manual` startup if `Disabled` |
| 6 | Trigger policy scan | `usoclient StartScan` (non-fatal if unavailable) |

## Configuration

```powershell
# --- WUDUP-Remediate.ps1 ---
$Config_AllowOnSCCM = $false   # $true to force remediation on SCCM-managed devices

# --- WUDUP-Detect.ps1 ---
$Config_RequireUpdateRing = $false    # $true to require Intune/co-mgmt Update Ring delivery
$Config_RequireMDMEnrollment = $false # $true to require active MDM enrollment
$Config_MaxScanAgeDays = 0            # Max days since last WU scan (0 = disabled)
```

## Deployment in Intune

1. Navigate to **Devices > Remediations** (or **Proactive remediations**)
2. Create a new remediation script package
3. Upload `WUDUP-Detect.ps1` as the detection script
4. Upload `WUDUP-Remediate.ps1` as the remediation script
5. Set **Run this script using the logged-on credentials** to **No** (runs as SYSTEM)
6. Assign to your target device groups

## Logging

Both scripts log to `%ProgramData%\WUDUP\Logs\`:
- `detect.log` — detection results with timestamps
- `remediate.log` — remediation actions with timestamps

Logs are append-only and persist across runs for troubleshooting.
