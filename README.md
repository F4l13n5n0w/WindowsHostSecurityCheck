# Windows local host security assessment

**windows_security_check_v3.ps1** combines local Windows enumeration, security configuration review, finding verification and report refresh in one standalone script. Copy this one file to the target server; it needs no project helper scripts or reference files. It writes timestamped JSON, TXT, HTML, and SHA256 manifests under **HostSecurityReport** by default.

## Native TLS/SSL scanner

**testssl.ps1** is a separate native Windows network scanner inspired by [testssl.sh](https://github.com/testssl/testssl.sh). It checks SSL/TLS protocol selection, 46 listed cipher suites, certificate/trust/name/validity, selected HTTP policies and five STARTTLS services. It requires no OpenSSL, Docker, WSL or helper scripts. Specialized checks it cannot reproduce are explicitly marked unsupported; it does not claim full testssl.sh parity.

~~~powershell
.\testssl.ps1 -Target 'https://server.example:443' -OutputDirectory 'C:\Temp\TLSReport'
.\testssl.ps1 -Target 'mail.example:25' -StartTls smtp -Checks Protocols,Ciphers,Certificate,Extensions
~~~

It creates its own timestamped JSON/TXT/HTML/CSV reports and SHA256 manifests. HTML findings are sortable and include explanations, repeatable commands and saved evidence. See [the upstream review, coverage comparison and usage guide](docs/testssl-review.md) before interpreting results. Test it with **tests/Test-Tls.ps1** on PowerShell 5.1 or 7.

## Run

Use 64-bit Windows PowerShell 5.1, preferably elevated for complete collection:

~~~powershell
.\windows_security_check_v3.ps1 -OutputDirectory C:\Temp\HostSecurityReport -SkipWindowsUpdateScan
~~~

Omit **-SkipWindowsUpdateScan** to search for missing software updates through Windows Update Agent. That search may contact the configured update service; it does not install updates. Collection otherwise targets the local machine. The script writes reports and a temporary secedit policy export; it does not remediate settings.

Designed originally for Server 2022; client Windows checks now run when the corresponding APIs are available. Missing modules, permissions, or unsupported firmware can limit results. Windows PowerShell 5.1 has the broadest inbox-module compatibility. PowerShell 7 syntax and isolated tests are also checked, but module availability differs.

Add **-RunVerification** to execute supported verification checks after a fresh scan, before writing the reports:

~~~powershell
.\windows_security_check_v3.ps1 -OutputDirectory C:\Temp\HostSecurityReport -SkipWindowsUpdateScan -RunVerification -TimeoutSeconds 30
~~~

The same execution token is used for collection and verification. Elevation improves collection coverage; use a non-elevated session to assess the tested user's write access. You can refresh an elevated scan's JSON in a non-elevated session on the same host using the mode below.

## Run verification on an existing report

Run v3 with **-InputJson** on the same Windows host as the original scan. This mode skips host collectors and preserves the historical scan. Use a non-elevated session first when assessing access available to a standard user:

~~~powershell
.\windows_security_check_v3.ps1 -InputJson 'C:\Temp\HostSecurityReport\your-report.json' -RunVerification -TimeoutSeconds 30
~~~

The script regenerates JSON, TXT, HTML and hashes in a separate **with_verification** folder. Each finding gains a `VerificationResult`: the executed commands, full captured selected output, separate errors/warnings/information streams, timestamps, duration, execution identity and explanations. HTML places collapsible transcripts under **Next verification steps** and highlights relevant permission values and successful write-open results in red. Source evidence and severity remain intact; a completed check does not confirm exploitation or disprove the historical finding.

Supported plans cover task/service permissions and execution context, autoruns, startup/PATH/DLL permissions, installer policies, current privileges, and local configuration findings such as Defender, firewall, SMB, UAC, logging and security policies. Commands come from the script's maintained code; strings stored in report commands are never executed. Unsupported findings get an explicit explanation. A fresh Windows Update Agent search is excluded because it can contact an update service; rerun the main scan to refresh that finding. Missing modules, permission failures, empty responses and timeouts are recorded, with any partial output retained.

The timeout is per command block (1–300 seconds), not the whole report. Verification may take several minutes on reports with many findings. Existing-file probes open a write handle and close it without writing bytes; no task/service action is changed or launched. Local password-policy checks use temporary secedit exports and clean them up. User-scoped results apply to the recorded verification user. Elevated write access is not evidence that a standard user can write. The script checks `Metadata.Host` against the local computer name before execution.

Omit **-RunVerification** to refresh suggested commands without executing checks. Older executed transcripts, if already present in the input, retain their original timestamps.

The v2 script and files under **tools** remain available for older workflows. V3 contains their runtime functions and does not load them. **-SkipWindowsUpdateScan** applies only to fresh scans and cannot be combined with **-InputJson**. **-OutputDirectory** can override either mode's destination; report refresh rejects overwriting the input JSON.

## Report improvements

V3.1 adds **Get-InstalledSoftwareDllAssessment**, enabled during fresh scans. Installed-software DLL injection/sideloading analysis is written to a **separate `_DllAnalysis` report**, with its own JSON, TXT, HTML index and SHA256 manifest. The main host report links to this index and excludes the DLL analysis findings and nested evidence; each report has its own severity counts. Other host PATH/DLL configuration checks remain in the host report.

The DLL HTML index links to findings and inventoried applications in lists of at most 100 rows. Each finding opens a separate page containing its full command, saved response, highlighted evidence, abuse explanation and verification transcript. Application evidence is split into pages of at most 25 records. Lists are sortable and filterable; finding pages start in severity order across pages, while sorting/filtering acts on the current page. Full DLL JSON/TXT exports retain all collected records. Keep the `_DllAnalysis_Details` folder beside the HTML index when copying reports; both manifests cover the detail pages. No external assets or web server are required.

To split an existing large combined v3 JSON without rescanning or running verification:

~~~powershell
.\windows_security_check_v3.ps1 -InputJson 'C:\Temp\HostSecurityReport\your-report.json' -OutputDirectory 'C:\Temp\HostSecurityReport\split_reports'
~~~

The original report is preserved. Add **-RunVerification** only to collect fresh verification output on the original host. A separate DLL JSON can also be refreshed directly using **-InputJson**.

Application pages include explicit missing-path, skipped, partial and unavailable results. Inventory covers machine/current-user uninstall registry entries and available AppX/MSIX registrations (all users when elevated, otherwise the executing user). Portable applications and unloaded user registry profiles can remain outside inventory; collection errors identify inaccessible sources.

The review reads PE32/PE32+ static and delay-import tables, retains every selected import record, and checks DLL files and parent directories for applicable broad mutation Allow ACEs by SID. Deny and inheritance flags are retained; these heuristics do not calculate effective access. Missing app-local imports in broadly writable locations, writable DLLs and DLL parent permission candidates become **Review** findings with full evidence and repeatable verification commands. KnownDLL/API-set imports are excluded from ordinary missing-file candidates. Service/task identities are correlated where registered executable paths match. The binary is read as data, never loaded or executed.

For visible running processes inside installation roots, a handle-only native probe requests **0x043A** (create-thread, query-information, VM-operation, VM-read and VM-write access) and immediately closes the handles. It checks the actual image path to guard against PID reuse and records caller/target SIDs and integrity levels. Cross-user or higher-integrity grants from a non-elevated caller produce Review findings; same-context and elevated-administrator access remain observations. No process memory is accessed, thread created, DLL injected, privilege enabled or application started. Access denial and unknown target identity remain observations, not proof that every injection technique is blocked.

Windows can redirect or restrict DLL loading through manifests, API sets, KnownDLLs, package graphs, loaded modules and search APIs. Static imports do not reveal all dynamic, .NET or plugin loads, and a DLL next to another DLL is not necessarily in the application's effective search path. These checks identify candidates; a normal application load trace and execution identity are needed to establish an actual route. Signature status is not used to declare an application safe or vulnerable. Implementation follows Microsoft's [DLL search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order), [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), and [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) documentation.

The default budget is **20000 filesystem entries**, **1000 recorded DLL candidates** and **120 seconds per installation root**, checked between local operations; a blocking OS call can exceed the time budget. Use **-DllScanMaxCandidatesPerSoftware** to raise the candidate limit when needed. Duplicate roots are cached. Reparse points, remote/mapped drives, and overly broad drive/Windows/Program Files roots are excluded. Budget exhaustion, malformed binaries and permission failures are reported as incomplete coverage.

~~~powershell
# Adjust the software review budget during a normal scan:
.\windows_security_check_v3.ps1 -SkipWindowsUpdateScan -DllScanMaxFilesPerSoftware 50000 -DllScanTimeoutSeconds 300

# Keep inventory rows but omit this review:
.\windows_security_check_v3.ps1 -SkipWindowsUpdateScan -SkipSoftwareDllScan
~~~

Existing JSON refresh rechecks saved DLL findings with **-RunVerification**. Refresh does not perform a new software inventory; rerun a fresh scan to discover new candidates. Verification reruns selected import/ACL or process-access queries without planting DLLs or launching applications.

- The sortable **Next verification steps** column includes finding-specific commands for services, scheduled tasks, autoruns, PATH/DLL checks, installer policy and sensitive user rights. Commands are collapsible, selectable and copyable; JSON/TXT retain the same `VerificationSteps` field.
- Verification commands inspect identity, execution context and full permission entries. Existing-file write probes open and close a handle without writing bytes. Run them in a non-elevated session and paste each complete `try/catch/finally` block together. Directory and registry ACL observations do not prove effective write access.
- Scheduled-task steps use separate path formats: cmdlets need a trailing backslash; COM `GetFolder()` rejects it. Each block defines its own variables and reports scheduler-query errors without cascading null-object errors.
- New task evidence includes group principals, logon type, enabled/demand-start settings, all executable/COM actions and trigger metadata. Task-definition findings are emitted once per task and marked **Review**: a broad Allow ACE is not proof of higher-privilege execution.
- Existing reports can be refreshed without a host scan using `windows_security_check_v3.ps1 -InputJson <report.json>`. Refreshed artifacts are written to a separate `with_verification` directory. Their metadata identifies the source scan and refresh time; findings retain their evidence and severity, while counts reflect the host/DLL partition.

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

Full scan evidence means all already-selected collection fields and records, not every property exposed by the OS or a command transcript. The main scan does not rerun displayed commands; verification mode separately records actual executed commands and responses when **-RunVerification** is supplied. Credential collection exclusions still apply. Serialization uses a depth limit of 100 and treats serialization warnings as errors rather than silently dropping deep data. Large reports can consume more memory and take longer to render.

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

Tests use synthetic inputs and isolated fixtures; they do not perform a full host scan. The DLL test additionally queries access to its own test process and an invalid PID to validate native handle/token handling without injection. V3 is tested in isolated folders without helpers, covering report refresh and scan orchestration with synthetic collector data.

~~~powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Assessment.ps1
pwsh -NoProfile -File .\tests\Test-Assessment.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Verification.ps1
pwsh -NoProfile -File .\tests\Test-Verification.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-SoftwareDll.ps1
pwsh -NoProfile -File .\tests\Test-SoftwareDll.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-ReportSplit.ps1
pwsh -NoProfile -File .\tests\Test-ReportSplit.ps1
~~~

The test command's execution-policy override is limited to that process. Tests generate **tests/artifacts/sample-report.html**, **empty-report.html**, and synthetic JSON. Open the sample report to inspect the report design without assessing a machine.

Test coverage includes service ACE parsing, error propagation, metadata-only registry existence, new finding conditions, password edge cases, command syntax/quoting, severity ordering, empty reports, and HTML injection escaping. Full collection still needs validation on the Windows versions and roles where it will be deployed.
