# Windows local host security assessment

**windows_security_check_v2.ps1** is a standalone local Windows enumeration and configuration review script. It writes timestamped JSON, TXT, HTML, and SHA256 manifests under **HostSecurityReport** by default.

## Run

Use 64-bit Windows PowerShell 5.1, preferably elevated for complete collection:

~~~powershell
.\windows_security_check_v2.ps1 -OutputDirectory C:\Temp\HostSecurityReport -SkipWindowsUpdateScan
~~~

Omit **-SkipWindowsUpdateScan** to search for missing software updates through Windows Update Agent. That search may contact the configured update service; it does not install updates. Collection otherwise targets the local machine. The script writes reports and a temporary secedit policy export; it does not remediate settings.

Designed originally for Server 2022; client Windows checks now run when the corresponding APIs are available. Missing modules, permissions, or unsupported firmware can limit results. Windows PowerShell 5.1 has the broadest inbox-module compatibility. PowerShell 7 syntax and isolated tests are also checked, but module availability differs.

## Report improvements in 2.3

- The sortable **Next verification steps** column includes finding-specific commands for services, scheduled tasks, autoruns, PATH/DLL checks, installer policy and sensitive user rights. Commands are collapsible, selectable and copyable; JSON/TXT retain the same `VerificationSteps` field.
- Verification commands inspect identity, execution context and full permission entries. Existing-file write probes open and close a handle without writing bytes. Run them in a non-elevated session and paste each complete `try/catch/finally` block together. Directory and registry ACL observations do not prove effective write access.
- Scheduled-task steps use separate path formats: cmdlets need a trailing backslash; COM `GetFolder()` rejects it. Each block defines its own variables and reports scheduler-query errors without cascading null-object errors.
- New task evidence includes group principals, logon type, enabled/demand-start settings, all executable/COM actions and trigger metadata. Task-definition findings are emitted once per task and marked **Review**: a broad Allow ACE is not proof of higher-privilege execution.
- Existing reports can be refreshed without a host scan using `tools/Update-ReportVerification.ps1 -InputJson <report.json>`. Refreshed artifacts are written to a separate `with_verification` directory. Their metadata identifies the source scan and refresh time; historical finding counts and collection results remain intact.

- All HTML report groups are collapsible, with expand/collapse-all controls and section links.
- Findings start in Critical → High → Medium → Low → Informational order, even without JavaScript.
- Every findings column can be sorted in either direction; text search filters all columns.
- Every finding has a repeatable PowerShell command, also present in JSON and TXT.
- Command and evidence cells use selectable, wrapping terminal-style blocks. Copy buttons select text when clipboard access is unavailable.
- Each evidence cell includes a PowerShell command prompt followed by the complete saved response. Red marks the specific values or permission entries relevant to the finding; unrelated evidence stays visible. Where there is no single raw triggering value, the assessment observation is highlighted separately.
- Commands are repeatable collection commands, not a claim that their exact text was executed to produce a verbatim transcript. The response is the saved selected collection data. Highlighting also applies to review observations and does not prove exploitability.
- Evidence retains the complete objects selected by each collector, including nested values, long strings, and every array entry. PowerShell display views no longer truncate the evidence.
- Each finding keeps its observation separately from full evidence. JSON exposes EvidenceSummary, EvidenceData (structured), and Evidence (readable serialization).
- The sortable **How to exploit** column explains the abuse scenario, prerequisites, and limitations for each finding. JSON and TXT include the same HowToExploit field. Informational observations do not imply a confirmed exploit.
- TXT now contains every report group using full serialization; HTML evidence has no vertical height cap.
- Report content is HTML-encoded. The report requires no external scripts, fonts, or stylesheets.
- HTML includes every top-level JSON evidence group, including installed software, processes, and additional check results.

Commands are for the same machine and execution identity. Some need elevation or optional modules. Policy-review commands create and clean up a temporary export. Missing registry settings may produce an error when a command is repeated; that differs from an explicit disabled value.

Full evidence means all already-selected collection fields and records, not every property exposed by the OS or a command transcript. Commands are not rerun to collect evidence. Credential collection exclusions still apply. Serialization uses a depth limit of 100 and treats serialization warnings as errors rather than silently dropping deep data. Large reports can consume more memory and take longer to render.

Abuse descriptions explain conditional mechanisms; the script does not attempt exploitation. Service-path and service-permission explanations were checked against MITRE ATT&CK [unquoted paths](https://attack.mitre.org/techniques/T1574/009/), [service binaries](https://attack.mitre.org/techniques/T1574/010/), and [service registry permissions](https://attack.mitre.org/techniques/T1574/011/). Installer-policy behavior follows Microsoft's [AlwaysInstallElevated documentation](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated).

## Reference comparison

The review used the local **reference/winPEAS.ps1.txt** and all four pages in **reference/links.txt**:

- [Seatbelt](https://github.com/GhostPack/Seatbelt): host-survey coverage and local configuration inventory.
- [PrivescCheck](https://github.com/itm4n/PrivescCheck), including its [hardening checks](https://github.com/itm4n/PrivescCheck/blob/master/src/check/Hardening.ps1): policy checks and the importance of execution context for access-control results.
- [ired.team enumeration and discovery](https://www.ired.team/offensive-security/enumeration-and-discovery): account and mapped-drive enumeration.
- [ired.team privilege escalation](https://www.ired.team/offensive-security/privilege-escalation), especially [IFEO](https://www.ired.team/offensive-security/privilege-escalation/t1183-image-file-execution-options-injection): additional registry-based review points.

Existing coverage retained: OS and hardware, local accounts and administrators, user rights, password policy, UAC, AlwaysInstallElevated, Defender, firewall, listening ports, SMB, NTLM, RDP, WinRM, logging, Credential Guard/VBS, AppLocker/WDAC, services, scheduled tasks, autorun registry entries, PATH/DLL configuration, TLS/LDAP indicators, software and patch inventory.

Eighteen additional check groups are in **Get-AdditionalHostChecks**:

| Added check | Output / finding behavior | Reference overlap |
|---|---|---|
| Point and Print | Flags explicit permission for non-admin driver installation; absent values are not treated as vulnerable | winPEAS, PrivescCheck |
| WSUS transport | Reviews HTTP only when UseWUServer=1 | winPEAS, PrivescCheck |
| Windows and legacy LAPS | Policy indicators from CSP, Group Policy, local configuration, and legacy roots | winPEAS, Seatbelt, PrivescCheck |
| Secure Boot | Reviews an explicit false result; unsupported/inaccessible firmware is unavailable | Seatbelt, PrivescCheck |
| BitLocker | Reviews OS-volume protection off; exports no recovery protectors | PrivescCheck |
| PowerShell optional features | Reviews enabled v2 components | Seatbelt / legacy-engine coverage |
| Event Forwarding | Enumerates subscription-manager policy | winPEAS, Seatbelt |
| Process command-line auditing | Reviews explicitly disabled command-line inclusion | winPEAS / audit coverage, ired.team |
| IFEO debugger redirects | Reviews both registry views and nested debugger entries | ired.team |
| Permanent WMI bindings | Reviews registered filter-to-consumer bindings | Local persistence inventory addition |
| Startup folders | Enumerates current-user/all-users folders and broad write ACEs | winPEAS / startup coverage |
| Unattended setup artifacts | Known-path file metadata only; presence is informational | winPEAS, PrivescCheck |
| Local group memberships | All local groups, with per-group collection errors | winPEAS, Seatbelt, ired.team |
| Established TCP connections | Local/remote endpoints and owning PID | Seatbelt |
| Neighbor cache | Existing IPv4/IPv6 neighbor entries; no probing | winPEAS, Seatbelt |
| DNS client cache | Existing cached records; no DNS discovery queries | winPEAS, Seatbelt |
| Mapped network drives | Local mapping metadata | Seatbelt, ired.team |
| Registered antivirus | SecurityCenter2 product metadata on supported clients | winPEAS, Seatbelt |

Policy semantics were cross-checked against Microsoft's [Point and Print guidance](https://support.microsoft.com/help/5005652), [LAPS policy settings](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings), [Secure Boot cmdlet](https://learn.microsoft.com/powershell/module/secureboot/confirm-securebootuefi), and [BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide).

LAPS rows report configured indicators only: they do not resolve effective policy precedence or establish successful password rotation. WEF policy presence does not establish successful forwarding. A registered WMI binding or debugger entry can be legitimate. Antivirus inventory does not establish product health.

Not imported from the references: credential extraction/decryption, Wi-Fi passwords, clipboard/history content, recursive password searches, exploit execution, remote AD enumeration, and historical hard-coded CVE/patch lists. These exceed this script's local configuration-assessment scope. Other advanced checks, such as named-pipe effective access, vulnerable-driver matching, and complete COM/task action analysis, remain outside this implementation.

## Reliability fixes

The service SDDL check now reads ACE types, trustee SIDs and permission masks instead of matching substrings across the entire ACE. Broad read-only grants and deny entries are no longer mistaken for write grants. Standard-user ACL checks remain broad-principal heuristics; they do not compute effective access across deny entries, all group memberships, or every path ancestor.

AutoLogon password presence uses registry value names only. The zero-character password-minimum case is checked; missing UAC data is not labeled disabled. Built-in Guest and Administrators identification uses SIDs. Safe-command collection errors are recorded, and new check groups distinguish Collected, No data, Partial, Unavailable, and Evaluation failed. Output-write failures stop completion rather than printing a successful report path.

This is a configuration review, not a compliance certification or proof of exploitability. Existing checks do not all distinguish OS defaults from missing data. User-scoped checks cover the executing identity. Inspect collection errors alongside findings.

## Verification

Tests load function definitions and synthetic inputs only; they do not execute host enumeration.

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Assessment.ps1
pwsh -NoProfile -File .\tests\Test-Assessment.ps1
~~~

The test command's execution-policy override is limited to that process. Tests generate **tests/artifacts/sample-report.html**, **empty-report.html**, and synthetic JSON. Open the sample report to inspect the report design without assessing a machine.

Test coverage includes service ACE parsing, error propagation, metadata-only registry existence, new finding conditions, password edge cases, command syntax/quoting, severity ordering, empty reports, and HTML injection escaping. Full collection still needs validation on the Windows versions and roles where it will be deployed.
