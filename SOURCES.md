# WUDUP Data Sources Reference

This document catalogs every data source that WUDUP reads, organized by category. Each entry describes what the source provides, what values are read, and why.

---

## Windows Services

### wuauserv (Windows Update Agent)

- **Method**: `Get-Service -Name 'wuauserv'`
- **Properties**: `Status`, `StartType`
- **Purpose**: The core Windows Update client service. Handles scanning, downloading, and installing updates. Runs as demand-start and is often stopped when idle (normal behavior). If disabled, no updates will be processed.
- **Used in**: `Get-WUServiceState`

### UsoSvc (Update Orchestrator Service)

- **Method**: `Get-Service -Name 'UsoSvc'`
- **Properties**: `Status`, `StartType`
- **Purpose**: Modern orchestration layer (Windows 10 1809+). Coordinates update scheduling and initiates wuauserv on demand. If UsoSvc is disabled, updates cannot be initiated even if wuauserv is functional. A stopped UsoSvc with a running wuauserv is normal during active operations.
- **Used in**: `Get-WUServiceState`

### ccmexec (SCCM/ConfigMgr Client Agent)

- **Method**: `Get-Service -Name 'ccmexec'`
- **Properties**: Existence check only
- **Purpose**: Detects whether the SCCM/ConfigMgr client is installed. Combined with the `HKLM:\SOFTWARE\Microsoft\CCM` registry check for reliable SCCM detection. This is the standard Microsoft-recommended client-side detection method.
- **Used in**: `Get-ManagementAuthority`

---

## COM Objects

### Microsoft.Update.SystemInfo

- **Method**: `New-Object -ComObject Microsoft.Update.SystemInfo`
- **Properties**: `RebootRequired` (boolean)
- **Purpose**: Authoritative pending reboot status. This is the same source the Windows Settings app queries. More reliable than registry flags, which can be stale (especially CBS `RebootPending`). Registry flags are retained as supplemental detail.
- **Used in**: `Get-UpdateStatus`

### Microsoft.Update.Session

- **Method**: `New-Object -ComObject Microsoft.Update.Session`
- **Properties**: `CreateUpdateSearcher()` → searcher; `QueryHistory()` on the searcher object
- **Purpose**: Queries the local Windows Update history log. Used to retrieve the last 10 installed/failed updates with title, date, and result code. Same data visible in Settings → Windows Update → Update History.
- **Used in**: `Get-RecentUpdateHistory`

### Microsoft.Update.ServiceManager

- **Method**: `New-Object -ComObject Microsoft.Update.ServiceManager`
- **Properties**: `Services` collection → each service has `Name`, `ServiceID`, `IsRegisteredWithAU`, `IsDefaultAUService`
- **Purpose**: Enumerates update service registrations from the Windows Update agent at runtime. Shows which services (Windows Update, Microsoft Update, WSUS, etc.) are registered and which is the active Automatic Update source. Complements registry-based detection with live agent state.
- **Used in**: `Get-RegisteredUpdateServices`

---

## WMI/CIM Classes

### Win32_OperatingSystem

- **Method**: `Get-CimInstance -ClassName Win32_OperatingSystem`
- **Properties**: `Caption`, `OSArchitecture`
- **Purpose**: Retrieves the human-readable OS name (e.g., "Microsoft Windows 11 Pro") and architecture. Falls back to registry values if CIM is unavailable.
- **Used in**: `Get-OSInfo`

---

## Registry Sources

### Group Policy: Windows Update

**Path**: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`

The primary location for Group Policy-delivered Windows Update settings. When Intune delivers ADMX-backed policies, they also write here.

| Value Name | Type | Description |
|---|---|---|
| `WUServer` | REG_SZ | WSUS server URL. Only honored when `UseWUServer=1` in the AU subkey. |
| `WUStatusServer` | REG_SZ | WSUS reporting server URL. Usually matches `WUServer`. |
| `DoNotConnectToWindowsUpdateInternetLocations` | DWORD | When `1`, blocks the WU client from reaching public Microsoft endpoints. Only applies when WSUS is configured. Breaks Store connectivity. |
| `SetDisableUXWUAccess` | DWORD | When `1`, hides the "Check for updates" button in Settings. Legacy on Windows 11 (no effect). |
| `SetPolicyDrivenUpdateSourceForFeatureUpdates` | DWORD | `0`=Windows Update (WUfB), `1`=WSUS. Most definitive WUfB signal on Windows 10 2004+/11. Added with KB5005101 (Sept 2021). |
| `SetPolicyDrivenUpdateSourceForQualityUpdates` | DWORD | Same as above, for quality/cumulative updates. |
| `SetPolicyDrivenUpdateSourceForDriverUpdates` | DWORD | Same as above, for driver updates. |
| `SetPolicyDrivenUpdateSourceForOtherUpdates` | DWORD | Same as above, for definition updates and other content. |
| `DeferFeatureUpdatesPeriodInDays` | DWORD | Feature update deferral (0-365 days). GP writes this as `DeferFeatureUpdatesPeriodinDays` (lowercase 'i') but registry is case-insensitive. |
| `DeferQualityUpdatesPeriodInDays` | DWORD | Quality update deferral (0-30 days). |
| `ConfigureDeadlineForFeatureUpdates` | DWORD | Feature update compliance deadline (CSP/MDM name). GP writes this as `ComplianceDeadlineForFU`. Both names are checked. |
| `ComplianceDeadlineForFU` | DWORD | Feature update compliance deadline (GP-native name). Fallback when `ConfigureDeadlineForFeatureUpdates` is absent. |
| `ConfigureDeadlineForQualityUpdates` | DWORD | Quality update compliance deadline (CSP/MDM name). GP writes this as `ComplianceDeadline`. Both names are checked. |
| `ComplianceDeadline` | DWORD | Quality update compliance deadline (GP-native name). Fallback when `ConfigureDeadlineForQualityUpdates` is absent. |
| `ConfigureDeadlineGracePeriod` | DWORD | Grace period before forced reboot (CSP name). GP-native name: `ComplianceGracePeriod`. |
| `ComplianceGracePeriod` | DWORD | Grace period (GP-native name). Fallback for `ConfigureDeadlineGracePeriod`. |
| `ConfigureDeadlineGracePeriodForFeatureUpdates` | DWORD | Feature-specific grace period (CSP name). GP-native name: `ComplianceGracePeriodForFU`. |
| `ComplianceGracePeriodForFU` | DWORD | Feature grace period (GP-native name). Fallback for the above. |
| `TargetReleaseVersion` | DWORD | `1`=version pinning enabled, `0` or absent=disabled. |
| `TargetReleaseVersionInfo` | REG_SZ | Target version string (e.g., `24H2`). Only effective when `TargetReleaseVersion=1`. |
| `ProductVersion` | REG_SZ | Target product (e.g., `Windows 11`). Used with `TargetReleaseVersionInfo`. |
| `UpdateServiceUrlAlternate` | REG_SZ | Alternate/fallback WSUS URL. Used when the primary `WUServer` is unreachable. Removed by WUDUP alongside `WUServer` when switching to WUfB. |
| `BranchReadinessLevel` | DWORD | Servicing channel. Legacy on Windows 11 (only General Availability exists). Values: `2`=Insider Fast, `4`=Insider Slow, `8`=Release Preview, `16`=Semi-Annual Channel (Targeted), `32`=General Availability Channel, `64`=Release Preview (Quality Updates Only), `128`=Canary Channel. |
| `ManagePreviewBuilds` | DWORD | `0`=disable preview, `1`=disable when next release public, `2`=enable, `3`=user choice. Not deprecated. |
| `ExcludeWUDriversInQualityUpdate` | DWORD | `1`=exclude drivers from WU quality updates, `0`=include (default). |
| `DisableDualScan` | DWORD | `1`=suppress dual-scan behavior. Legacy, deprecated on Windows 11. Replaced by PolicyDrivenSource keys. |
| `PauseFeatureUpdatesStartTime` | REG_SZ | Feature update pause start (ISO 8601). Policy-driven pause. |
| `PauseFeatureUpdatesEndTime` | REG_SZ | Feature update pause end (ISO 8601). |
| `PauseQualityUpdatesStartTime` | REG_SZ | Quality update pause start (ISO 8601). |
| `PauseQualityUpdatesEndTime` | REG_SZ | Quality update pause end (ISO 8601). |

### Group Policy: Auto Update

**Path**: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`

AU-specific policies controlling download/install behavior, scheduling, and active hours.

| Value Name | Type | Description |
|---|---|---|
| `UseWUServer` | DWORD | `1`=honor WUServer/WUStatusServer URLs, `0` or absent=use Microsoft Update directly. This is the WSUS "on switch". |
| `UseUpdateClassPolicySource` | DWORD | `1`=honor PolicyDrivenSource keys. Required when setting PolicyDrivenSource via direct registry write (not GPO/CSP). GPO and CSP set this automatically. |
| `NoAutoUpdate` | DWORD | `1`=disable automatic updates entirely, `0`=enabled. |
| `AUOptions` | DWORD | Auto-update behavior: `1`=AU disabled, `2`=notify before download, `3`=auto download + notify install, `4`=auto download + scheduled install, `5`=local admin choice (not valid Win 10+), `7`=notify install + notify restart (Server 2016+ only). |
| `ScheduledInstallDay` | DWORD | `0`=every day, `1-7`=Sunday-Saturday. Only used when `AUOptions=4`. |
| `ScheduledInstallTime` | DWORD | Hour (0-23) for scheduled installs. Only used when `AUOptions=4`. |
| `AlwaysAutoRebootAtScheduledTime` | DWORD | `1`=force reboot at scheduled time after install, even with logged-in users. |
| `SetActiveHours` | DWORD | `1`=enforce policy-defined active hours. |
| `ActiveHoursStart` | DWORD | Active hours start (0-23). Updates won't force restart during active hours. |
| `ActiveHoursEnd` | DWORD | Active hours end (0-23). |

### MDM/Intune Policy

**Path**: `HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update`

Where Intune/MDM delivers update policies via the Update CSP (`./Device/Vendor/MSFT/Policy/Config/Update/`). Checked as secondary source after Group Policy path.

| Value Name | Type | Description |
|---|---|---|
| `SetPolicyDrivenUpdateSourceForFeatureUpdates` | DWORD | Same as GP equivalent. `0`=WU, `1`=WSUS. |
| `SetPolicyDrivenUpdateSourceForQualityUpdates` | DWORD | Same as GP equivalent. |
| `SetPolicyDrivenUpdateSourceForDriverUpdates` | DWORD | Same as GP equivalent. |
| `SetPolicyDrivenUpdateSourceForOtherUpdates` | DWORD | Same as GP equivalent. |
| `DeferFeatureUpdatesPeriodInDays` | DWORD | Feature update deferral (MDM-delivered). |
| `DeferQualityUpdatesPeriodInDays` | DWORD | Quality update deferral (MDM-delivered). |
| `ConfigureDeadlineForFeatureUpdates` | DWORD | Feature deadline (CSP name). |
| `ConfigureDeadlineForQualityUpdates` | DWORD | Quality deadline (CSP name). |
| `ConfigureDeadlineGracePeriod` | DWORD | Grace period (CSP name). |
| `ConfigureDeadlineGracePeriodForFeatureUpdates` | DWORD | Feature-specific grace period. |
| `BranchReadinessLevel` | DWORD | Servicing channel (MDM-delivered). |
| `ManagePreviewBuilds` | DWORD | Preview build management (MDM-delivered). |
| `ExcludeWUDriversInQualityUpdate` | DWORD | Driver exclusion (MDM-delivered). |

### MDM Enrollment

**Path**: `HKLM:\SOFTWARE\Microsoft\Enrollments\{GUID}`

Each MDM enrollment creates a GUID-named subkey. Enumerated to detect active enrollment.

| Value Name | Type | Description |
|---|---|---|
| `EnrollmentState` | DWORD | `1`=actively enrolled, `0`=not enrolled, `2`=enrollment requested, `3`=unenrollment requested. |
| `ProviderID` | REG_SZ | MDM provider identifier. `MS DM Server` = direct Intune enrollment. `WMI_Bridge_SCCM_Server` = SCCM co-management bridge (policies delivered via Intune through co-management). |

An active enrollment is `EnrollmentState=1` with a non-empty `ProviderID`. Used to distinguish live MDM management from stale/orphaned PolicyManager entries.

### UX Settings (User-Initiated)

**Path**: `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings`

Settings written by the Windows Update Settings app when users change preferences locally.

| Value Name | Type | Description |
|---|---|---|
| `PauseFeatureUpdatesStartTime` | REG_SZ | User-initiated feature pause start. Checked when GP path has no pause. |
| `PauseFeatureUpdatesEndTime` | REG_SZ | User-initiated feature pause end. |
| `PauseQualityUpdatesStartTime` | REG_SZ | User-initiated quality pause start. |
| `PauseQualityUpdatesEndTime` | REG_SZ | User-initiated quality pause end. |
| `PauseUpdatesExpiryTime` | REG_SZ | Consolidated pause expiry timestamp used by the Settings app. Single indicator covering all update types. |
| `FlightSettingsMaxPauseDays` | DWORD | Local feature deferral setting. Lowest priority after GP and MDM. |
| `ActiveHoursStart` | DWORD | User-set active hours start. Used when no policy-enforced active hours. |
| `ActiveHoursEnd` | DWORD | User-set active hours end. |
| `SmartActiveHoursState` | DWORD | Whether Windows auto-adjusts active hours based on usage patterns. |

### Update Policy Settings (Internal State)

**Path**: `HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings`

Internal tracking of pause state. Written by the WU client to reflect the resolved pause status.

| Value Name | Type | Description |
|---|---|---|
| `PausedFeatureDate` | REG_SZ | Date when feature updates were paused. |
| `PausedQualityDate` | REG_SZ | Date when quality updates were paused. |
| `PausedFeatureStatus` | DWORD | `1`=feature updates currently paused. Used as fallback when no explicit end date exists. |
| `PausedQualityStatus` | DWORD | `1`=quality updates currently paused. |

### Windows Update Auto Update Results

**Path**: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`

Historical results and pending reboot flag from the WU agent.

| Value Name / Subkey | Type | Description |
|---|---|---|
| `RebootRequired` (subkey existence) | Key | If this subkey exists, the WU agent has flagged a pending reboot. Supplemental to the COM API check. |
| `Results\Install\LastSuccessTime` | REG_SZ | Timestamp of last successful update installation. |
| `Results\Detect\LastSuccessTime` | REG_SZ | Timestamp of last successful update scan. |

### Component Based Servicing (CBS)

**Path**: `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing`

| Value Name / Subkey | Type | Description |
|---|---|---|
| `RebootPending` (subkey existence) | Key | CBS servicing reboot flag. Often stale after .NET framework updates, feature enablement, or other servicing operations that don't actually require a reboot for WU purposes. The Windows Settings app ignores this flag. Displayed as informational (yellow) when present without a COM API reboot signal. |

### SCCM/ConfigMgr

**Path**: `HKLM:\SOFTWARE\Microsoft\CCM`

| Value Name | Type | Description |
|---|---|---|
| (key existence) | Key | Combined with ccmexec service detection to confirm SCCM client installation. |
| `CoManagementFlags` | QWORD | Bitmask of workloads shifted to Intune in a co-managed environment. Bit 4 (value `16`) = Windows Update workload. If this bit is set, Intune manages WU policies; if not, SCCM retains control. A value of `8193` (base) means co-management is enabled but no workloads shifted. |

### OS Version Information

**Path**: `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

| Value Name | Type | Description |
|---|---|---|
| `ProductName` | REG_SZ | OS product name (e.g., "Windows 11 Pro"). |
| `DisplayVersion` | REG_SZ | Version display string (e.g., "24H2"). |
| `ReleaseId` | REG_SZ | Legacy release ID (e.g., "2009"). Deprecated in favor of `DisplayVersion`. |
| `CurrentBuild` | REG_SZ | OS build number (e.g., "26100"). |
| `UBR` | DWORD | Update Build Revision. Combined with `CurrentBuild` for full build string (e.g., "26100.1234"). |
| `EditionID` | REG_SZ | Edition (e.g., "Professional", "Enterprise"). |
| `InstallationType` | REG_SZ | Installation type (e.g., "Client", "Server"). |

### Delivery Optimization (Policy)

**Path**: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization`

| Value Name | Type | Description |
|---|---|---|
| `DownloadMode` | DWORD | `0`=HTTP only, `1`=LAN peers, `2`=Group (AD site), `3`=Internet, `99`=Simple (no peering + no fallback), `100`=Bypass (BITS only). Note: the GP registry value is `DownloadMode`, not `DODownloadMode` (which is the CSP/MDM name). |

### Delivery Optimization (MDM)

**Path**: `HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization`

| Value Name | Type | Description |
|---|---|---|
| `DODownloadMode` | DWORD | Same values as GP equivalent. Checked when GP path has no value. |

---

## Source Priority

When a setting can come from multiple sources, WUDUP reads in this priority order:

1. **Group Policy** (`HKLM:\...\Policies\...`) — highest priority
2. **MDM/Intune** (`HKLM:\...\PolicyManager\...`) — secondary
3. **UX Settings** (`HKLM:\...\WindowsUpdate\UX\Settings`) — user-initiated, lowest
4. **Internal state** (`HKLM:\...\UpdatePolicy\Settings`) — fallback for pause status

## Management Authority Priority

WUDUP determines the device's management authority in this order:

1. **SCCM/ConfigMgr** — ccmexec service + `HKLM:\SOFTWARE\Microsoft\CCM` (with co-management workload check)
2. **MDM/Intune** — Active enrollment in `HKLM:\SOFTWARE\Microsoft\Enrollments` (with `EnrollmentState=1`)
3. **WSUS** — `UseWUServer=1` + `WUServer` URL present (with split-source detection)
4. **WUfB/GPO** — Any WUfB indicator present (PolicyDrivenSource, deferrals, deadlines, etc.)
5. **Local** — No managed configuration detected

## Key Detection Concepts

**Split-source**: WSUS configured (`UseWUServer=1`) but `SetPolicyDrivenUpdateSourceFor*=0` directs some update types to Windows Update. This is a valid WUfB configuration, not a misconfiguration.

**Dual-scan**: WSUS active + WUfB deferral policies present, but NO PolicyDrivenSource override and `DisableDualScan` is not set. This is a misconfiguration where the WU client may scan both WSUS and Microsoft Update unpredictably.

**Stale MDM**: PolicyManager keys exist but no active enrollment in `HKLM:\SOFTWARE\Microsoft\Enrollments` (no subkey with `EnrollmentState=1`). Indicates a device was previously MDM-managed but enrollment was removed without cleaning up policies.
