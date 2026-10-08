#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Comprehensive Host Security Assessment

.DESCRIPTION
    Read-only host enumeration and security configuration assessment intended
    for authorised penetration testing and security reviews.

    Performs checks covering:
      - Host / OS / hardware information
      - Domain membership and identity
      - Local users / groups / administrators
      - Password and lockout policy
      - User rights / privileges
      - Microsoft Defender / exclusions / ASR
      - Firewall profiles and exposed inbound rules
      - TCP / UDP listening services
      - SMB security
      - NTLM / anonymous access
      - LDAP signing / channel binding indicators
      - RDP security
      - WinRM configuration
      - PowerShell logging
      - UAC
      - LSA / Credential Guard / VBS
      - WDigest
      - AppLocker
      - WDAC / Code Integrity
      - Services
      - Unquoted service paths
      - Writable service binaries / directories
      - Service registry ACLs
      - Service object SDDL review
      - Scheduled tasks
      - Writable task files / action binaries
      - Autorun locations
      - Writable autorun executables / directories
      - AlwaysInstallElevated
      - AutoLogon indicators (password is NOT collected)
      - PATH search-order weaknesses
      - DLL search configuration
      - Installed software
      - Windows updates / patch age
      - Pending reboot
      - Audit policy
      - Security / PowerShell event log configuration
      - Sysmon
      - LLMNR / NetBIOS
      - TLS / SSL / SCHANNEL
      - Windows shares
      - SHA256 hashes of generated evidence files

    Outputs:
      JSON
      TXT
      HTML
      SHA256 manifest

.PARAMETER InputJson
    Refresh an existing JSON report without running host collectors. Omit this
    parameter to perform a fresh scan. Refresh output defaults to with_verification
    beside the input report; the original JSON cannot be overwritten.

.PARAMETER RunVerification
    Execute supported local verification checks and include complete captured
    output and explanations. For fresh scans, checks run before writing reports.
    For existing reports, the scanned host must match this computer.

.PARAMETER TimeoutSeconds
    Per-verification-command timeout, from 1 to 300 seconds (default 30).

.EXAMPLE
    .\windows_security_check_v3.ps1 -SkipWindowsUpdateScan -RunVerification

.EXAMPLE
    .\windows_security_check_v3.ps1 -InputJson 'C:\Temp\HostSecurityReport\report.json' -RunVerification

.PARAMETER SkipSoftwareDllScan
    Skip installed-software DLL/import and process-access checks. Each inventoried
    application is still listed with a Skipped status.

.PARAMETER DllScanMaxFilesPerSoftware
    Maximum filesystem entries examined per installation root (default 20000).
    Budget exhaustion is Partial, not a security pass. Reparse points are skipped.

.PARAMETER DllScanMaxCandidatesPerSoftware
    Maximum recorded DLL candidates per installation root (default 1000).
    Exhaustion is Partial and limits report memory use; selected evidence is complete.

.PARAMETER DllScanTimeoutSeconds
    Soft per-installation-root time budget checked between file operations (default
    120 seconds). Blocking OS calls may exceed the budget.

.NOTES
    Designed for:
      Windows Server 2022
      Windows PowerShell 5.1+

    Also collects local Windows client configuration when its APIs are available.
    Run in 64-bit Windows PowerShell 5.1 for the broadest inbox-module coverage.
    Run elevated for the most complete results. User-scoped checks describe the
    executing identity, not every user on the host. Optional APIs may be absent.
    Windows Update Agent may contact the configured update service unless
    -SkipWindowsUpdateScan is specified.

    Version 3.1 adds installed-software DLL and process-access review
    and adds conditional exploitation context to HTML, JSON, and TXT findings.
    ACL findings identify broad allow entries, not complete effective access.

    This script does not:
      - Dump credentials
      - Read cached passwords
      - Extract LSA secrets
      - Dump SAM
      - Dump LSASS
      - Modify security configuration
      - Exploit identified weaknesses

.EXAMPLE
    .\windows_security_check_v3.ps1

.EXAMPLE
    .\windows_security_check_v3.ps1 `
        -OutputDirectory C:\Temp\HostAssessment

#>

[CmdletBinding(DefaultParameterSetName='Scan')]
param(
    [string]$OutputDirectory = '',
    [Parameter(ParameterSetName='Scan')]
    [switch]$SkipWindowsUpdateScan,
    [Parameter(ParameterSetName='Scan')]
    [switch]$SkipSoftwareDllScan,
    [Parameter(ParameterSetName='Scan')]
    [ValidateRange(1,1000000)] [int]$DllScanMaxFilesPerSoftware=20000,
    [Parameter(ParameterSetName='Scan')]
    [ValidateRange(1,3600)] [int]$DllScanTimeoutSeconds=120,
    [Parameter(ParameterSetName='Scan')]
    [ValidateRange(1,100000)] [int]$DllScanMaxCandidatesPerSoftware=1000,
    [Parameter(Mandatory=$true,ParameterSetName='Refresh')]
    [ValidateNotNullOrEmpty()]
    [string]$InputJson,
    [switch]$RunVerification,
    [ValidateRange(1,300)]
    [int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

function Test-IsAdministrator {

    try {

        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

        $Principal = New-Object Security.Principal.WindowsPrincipal(
            $Identity
        )

        return $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        return $false
    }
}

function Add-CollectionError {

    param(
        [string]$Component,
        [string]$Message
    )

    $script:Errors += [PSCustomObject]@{
        Component = $Component
        Error     = $Message
    }
}

function Invoke-SafeCommand {

    param(
        [string]$Name,
        [scriptblock]$ScriptBlock
    )

    try {

        $ErrorActionPreference = 'Stop'
        & $ScriptBlock
    }
    catch {

        Add-CollectionError `
            -Component $Name `
            -Message $_.Exception.Message

        return $null
    }
}

function Get-RegistryValue {

    param(
        [string]$Path,
        [string]$Name
    )

    try {

        if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
            $Key = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($Key.GetValueNames() -contains $Name) {
                return $Key.GetValue($Name)
            }
        }
    }
    catch {
        Add-CollectionError "Registry: $Path\$Name" $_.Exception.Message
    }

    return $null
}

function Test-RegistryValueExists {

    param(
        [string]$Path,
        [string]$Name
    )

    try {

        if (-not (Test-Path $Path)) {
            return $false
        }

        # Enumerate value names only; never retrieve the AutoLogon password.
        $Key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $Key.GetValueNames() -contains $Name
    }
    catch {

        return $false
    }
}

function Add-Finding {

    param(
        [ValidateSet(
            "Critical",
            "High",
            "Medium",
            "Low",
            "Informational"
        )]
        [string]$Severity,

        [string]$Category,
        [string]$Title,
        [string]$Status,
        $Evidence,
        [string]$Recommendation,
        [string]$Reference = "",
        [string]$Command = "",
        $EvidenceData,
        [string]$HowToExploit = "",
        [string]$VerificationSteps = ""
    )

    $Summary = Convert-ToSafeString $Evidence
    if (-not $PSBoundParameters.ContainsKey('EvidenceData')) { $EvidenceData = $Evidence }
    if ([string]::IsNullOrWhiteSpace($HowToExploit)) {
        $HowToExploit = Get-ExploitationContext -Title $Title -Category $Category
    }
    if ([string]::IsNullOrWhiteSpace($VerificationSteps)) {
        $VerificationSteps = Get-FindingVerificationSteps -Title $Title -Category $Category -EvidenceData $EvidenceData -Command $Command
    }
    $script:Findings += [PSCustomObject]@{

        Severity       = $Severity
        Category       = $Category
        Finding        = $Title
        Status         = $Status
        Evidence       = Convert-ToSafeString $EvidenceData
        EvidenceSummary = $Summary
        EvidenceData   = $EvidenceData
        Command        = $Command
        HowToExploit   = $HowToExploit
        VerificationSteps = $VerificationSteps
        Recommendation = $Recommendation
        Reference      = $Reference
    }
}

function Get-FileWriteVerificationCommand {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    # Open an existing file without truncation, writing bytes, or changing ACLs.
    return ('$VerifyFile = ' + (ConvertTo-PowerShellLiteral $Path) + [Environment]::NewLine + @'
(Get-Acl -LiteralPath $VerifyFile -ErrorAction Stop).Access |
    Format-List IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags
$VerifyHandle = $null
try {
    $VerifyHandle = [System.IO.File]::Open($VerifyFile, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    'Write-open succeeded for this token; no bytes were written.'
} catch {
    'Write-open failed (access denial or sharing conflict): ' + $_.Exception.Message
} finally {
    if ($null -ne $VerifyHandle) { $VerifyHandle.Dispose() }
}
# Success establishes file-write access only, not privileged execution.
'@)
}

function Get-FindingVerificationSteps {
    param([string]$Title, [string]$Category, $EvidenceData, [string]$Command)
    if ($Title -match '^Installed software DLL loading candidate|^Installed software process injection access') {
        try {return (@(Get-SoftwareDllVerificationPlan $EvidenceData -Injection:($Title -match 'process injection')) | ForEach-Object {$_.Command}) -join "`n`n"}
        catch {return '# Verification plan unavailable: '+$_.Exception.Message}
    }
    $Lines = New-Object 'System.Collections.Generic.List[string]'
    $Relevant = $Category -eq 'Privilege Escalation' -or
        $Title -match '^Sensitive user right|^AlwaysInstallElevated|^Startup folder|^Image File Execution Options'
    if (-not $Relevant) { return '' }
    $Lines.Add(@'
# Run in a non-elevated session; a genuine standard-user account is preferable.
# Paste each complete try/catch/finally block together.
whoami.exe /all
$VerifyIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$VerifyPrincipal = [Security.Principal.WindowsPrincipal]::new($VerifyIdentity)
$VerifyPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# False can mean a filtered administrator. Check deny-only groups in whoami output.
'@)
    switch -Regex ($Title) {
        '^Scheduled task ' {
            if ([string]::IsNullOrWhiteSpace($EvidenceData.TaskName) -or [string]::IsNullOrWhiteSpace($EvidenceData.TaskPath)) {
                $Lines.Add('# Task identity is missing from the saved evidence. Recollect task metadata before validating this finding.')
                break
            }
            $Lines.Add('$VerifyTaskPath = ' + (ConvertTo-PowerShellLiteral $EvidenceData.TaskPath))
            $Lines.Add('$VerifyTaskName = ' + (ConvertTo-PowerShellLiteral $EvidenceData.TaskName))
            $Lines.Add(@'
$VerifyTask = Get-ScheduledTask -TaskPath $VerifyTaskPath -TaskName $VerifyTaskName -ErrorAction Stop
$VerifyTask.Principal | Format-List UserId,GroupId,LogonType,RunLevel
$VerifyTask | Format-List TaskName,State
$VerifyTask.Settings | Format-List Enabled,AllowDemandStart
$VerifyTask.Actions | Format-List *
$VerifyTask.Triggers | Format-List *
# COM folder paths must NOT end in a backslash; cmdlet TaskPath values do.
try {
    $VerifyService = New-Object -ComObject 'Schedule.Service'
    $VerifyService.Connect()
    $VerifyFolderPath = $VerifyTaskPath.TrimEnd([char]92)
    if ([string]::IsNullOrEmpty($VerifyFolderPath)) { $VerifyFolderPath = '\' }
    $VerifyRegistered = $VerifyService.GetFolder($VerifyFolderPath).GetTask($VerifyTaskName)
    $VerifySddl = $VerifyRegistered.GetSecurityDescriptor(7)
    $VerifySddl
    $VerifyDescriptor = [Security.AccessControl.RawSecurityDescriptor]::new($VerifySddl)
    $VerifyDescriptor.DiscretionaryAcl | Select-Object AceType,AceFlags,SecurityIdentifier,
        @{Name='AccessMaskHex';Expression={'0x{0:X8}' -f $_.AccessMask}} | Format-Table -Wrap
} catch { 'Scheduler query failed: ' + $_.Exception.Message }
# Null UserId may indicate a GroupId principal. HighestAvailable alone does not establish SYSTEM execution.
# RunLevel does not reduce SYSTEM privileges. Disabled tasks need an additional enable/launch path.
'@)
            if ($Title -match '^Scheduled task definition') {
                $Lines.Add((Get-FileWriteVerificationCommand $EvidenceData.TaskFile))
            } elseif ($Title -match '^Scheduled task executable directory') {
                if ($EvidenceData.Action) {
                    $Lines.Add('$VerifyDirectory = Split-Path -Parent ' + (ConvertTo-PowerShellLiteral $EvidenceData.Action))
                    $Lines.Add('(Get-Acl -LiteralPath $VerifyDirectory -ErrorAction Stop).Access | Format-List *')
                }
                $Lines.Add('# Directory grants do not establish replacement rights or a loaded DLL. Review effective deny rules and the actual consumer.')
            } else { $Lines.Add((Get-FileWriteVerificationCommand $EvidenceData.Action)) }
            $Lines.Add('# A writable target plus a privileged identity is a candidate. Confirming execution requires a controlled test on a snapshot-backed clone.')
            break
        }
        '^Unquoted service|^Service executable|^Service registry|^Potentially broad service-object' {
            if ($EvidenceData.Name) {
                $Lines.Add('$VerifyServiceName = ' + (ConvertTo-PowerShellLiteral $EvidenceData.Name))
                $Lines.Add(@'
Get-CimInstance Win32_Service | Where-Object Name -eq $VerifyServiceName |
    Format-List Name,PathName,StartName,StartMode,State
sc.exe qc $VerifyServiceName
sc.exe sdshow $VerifyServiceName
# Review CHANGE_CONFIG/WRITE_DAC/WRITE_OWNER grants, deny ACEs and the current token.
# Read/query success does not prove service modification or restart permission.
'@)
            }
            if ($Title -match '^Service executable is writable') {
                $Lines.Add((Get-FileWriteVerificationCommand $EvidenceData.Executable))
            } elseif ($Title -match '^Service executable directory') {
                if ($EvidenceData.Directory) {
                    $Lines.Add('(Get-Acl -LiteralPath ' + (ConvertTo-PowerShellLiteral $EvidenceData.Directory) + ' -ErrorAction Stop).Access | Format-List *')
                }
            } elseif ($Title -match '^Service registry') {
                if ($EvidenceData.Name) {
                    $Lines.Add('$VerifyRegistryPath = ' + (ConvertTo-PowerShellLiteral ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $EvidenceData.Name)))
                    $Lines.Add('Get-ItemProperty -LiteralPath $VerifyRegistryPath -ErrorAction Stop | Format-List ImagePath,ObjectName')
                    $Lines.Add('(Get-Acl -LiteralPath $VerifyRegistryPath -ErrorAction Stop).Access | Format-List *')
                }
            } elseif ($Title -match '^Unquoted service') {
                if ($EvidenceData.Executable) {
                    $Lines.Add('$VerifyExecutable = ' + (ConvertTo-PowerShellLiteral $EvidenceData.Executable))
                    $Lines.Add(@'
# Review earlier executable candidates formed at spaces; do not create them.
foreach ($VerifySpace in [regex]::Matches($VerifyExecutable, ' ')) {
    $VerifyCandidate = $VerifyExecutable.Substring(0, $VerifySpace.Index) + '.exe'
    $VerifyParent = Split-Path -Parent $VerifyCandidate
    [pscustomobject]@{Candidate=$VerifyCandidate;Exists=(Test-Path -LiteralPath $VerifyCandidate);Parent=$VerifyParent}
    if (Test-Path -LiteralPath $VerifyParent) {
        (Get-Acl -LiteralPath $VerifyParent -ErrorAction Stop).Access | Format-List *
    }
}
# Spaces alone are insufficient. Confirm an earlier usable candidate, effective rights and a privileged launch.
'@)
                }
            }
            $Lines.Add('# Service account, usable effective rights and a subsequent launch determine whether elevation is possible.')
            break
        }
        '^Autorun executable' {
            if ($EvidenceData.RegistryPath) {
                $Lines.Add('Get-ItemProperty -LiteralPath ' + (ConvertTo-PowerShellLiteral $EvidenceData.RegistryPath) + ' -ErrorAction Stop | Format-List *')
            }
            if ($Title -match 'directory') {
                if ($EvidenceData.Executable) {
                    $Lines.Add('(Get-Acl -LiteralPath (Split-Path -Parent ' + (ConvertTo-PowerShellLiteral $EvidenceData.Executable) + ') -ErrorAction Stop).Access | Format-List *')
                }
            } else { $Lines.Add((Get-FileWriteVerificationCommand $EvidenceData.Executable)) }
            $Lines.Add('# Establish the user who consumes this entry and their token at logon. HKCU startup does not automatically elevate.')
            break
        }
        '^Startup folder|^System PATH' {
            if ($EvidenceData.Path) {
                $Lines.Add('(Get-Acl -LiteralPath ' + (ConvertTo-PowerShellLiteral $EvidenceData.Path) + ' -ErrorAction Stop).Access | Format-List *')
            }
            if ($Title -match '^System PATH') {
                $Lines.Add('[Environment]::GetEnvironmentVariable(''Path'',''Machine'') -split '';''')
                $Lines.Add('# Establish a privileged consumer, its actual search order and the specific executable or DLL it searches for.')
            } else { $Lines.Add('# Establish the affected logon identity. Review all-users versus current-user startup and effective directory rights.') }
            break
        }
        '^AlwaysInstallElevated' {
            $Lines.Add(@'
Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction Stop
Get-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction Stop
# Both values must be 1 for the tested user. Check application-control/installer restrictions before concluding execution is possible.
'@)
            break
        }
        '^Sensitive user right' {
            $Lines.Add('whoami.exe /priv')
            $Lines.Add('# Compare assigned principals with this token. Assignment is not proof the tested user holds a usable privilege; Disabled is not necessarily absent.')
            break
        }
        '^Safe DLL search' {
            $Lines.Add("Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name SafeDllSearchMode,CWDIllegalInDllSearch | Format-List")
            $Lines.Add('# Establish a privileged process loading a specific DLL through a writable searched directory. This policy alone is not an escalation path.')
            break
        }
        '^Image File Execution Options' {
            if ($Command) { $Lines.Add($Command) }
            $Lines.Add('# Review registry ACLs, debugger executable ACLs and the affected program execution identity. A debugger can be legitimate.')
            break
        }
        default {
            if ($Command) { $Lines.Add($Command) }
            $Lines.Add('# Establish effective access and a higher-privilege consumer. This observation alone does not confirm escalation.')
        }
    }
    return ($Lines -join [Environment]::NewLine)
}

function Convert-ToSafeString {

    param($Object)

    if ($null -eq $Object) {
        return ""
    }

    if ($Object -is [string]) { return $Object }
    # Serialize the selected collection objects, not PowerShell's display views.
    # A finite JSON depth is required by PowerShell; exceeding it must fail visibly.
    return ConvertTo-Json -InputObject $Object -Depth 100 -WarningAction Stop -ErrorAction Stop
}

function Convert-ArrayToText {

    param($Data)

    if ($null -eq $Data) {
        return "N/A"
    }

    return Convert-ToSafeString $Data
}

function Get-ExploitationContext {
    param([string]$Title, [string]$Category)
    # Explanations describe prerequisites and abuse paths, not confirmed exploitation.
    switch -Regex ($Title) {        '^Installed software DLL loading candidate' {return 'A user with effective DLL replacement/creation access might influence a DLL that an application really loads. Requires the exact loader lookup path, a usable grant and an application launch under the relevant identity; signatures, SxS/API sets/KnownDLLs and application-control rules can change the result. Static imports and broad Allow ACEs alone do not confirm sideloading or escalation.'}
        '^Installed software process injection access' {return 'Granted process access can be a prerequisite for remote memory/thread-based execution in that process, potentially crossing a user or integrity boundary. The probe only obtains and closes handles; target identity, process protections, code-integrity/dynamic-code policy, architecture and endpoint controls still determine whether DLL injection could execute.'}
        '^Unquoted service executable' { return 'A local user who can write an earlier executable candidate in the unquoted path could intercept service startup. Execution uses the service account. Requires a writable candidate, an actual service launch, and no blocking control; spaces alone are insufficient.' }
        '^Service executable is writable' { return 'A user with effective write access could replace the service executable. On its next start, the replacement runs as the configured service account. Requires a usable write grant and a restart or natural launch; elevation depends on the service identity.' }
        '^Service executable directory' { return 'A user with effective directory rights may be able to replace the executable or plant a dependency that the service actually loads. The next service launch can run it as the service identity. Directory write permission alone does not prove either path is usable.' }
        '^Service registry configuration' { return 'A user with effective configuration-write access could redirect a service executable or relevant service DLL setting. The changed configuration must be loaded on a subsequent service start. Impact depends on permitted values, service identity, and restart access.' }
        '^Potentially broad service-object' { return 'An allowed SERVICE_CHANGE_CONFIG grant can permit redirecting service execution; WRITE_DAC or WRITE_OWNER may permit obtaining such access. A service start and sufficient effective rights are still required. A broad allow ACE does not account for all deny rules.' }
        '^Scheduled task definition' { return 'If a user can alter a task definition and the scheduler accepts the change, the task may execute a substituted action as its run-as identity. File-write access alone does not establish that scheduler registration, caching, or integrity checks can be bypassed.' }
        '^Scheduled task executable' { return 'A user who can replace the task action executable, or a dependency it actually loads, could run code when the task next triggers. Privilege gain requires a task running as a more privileged identity and usable effective file permissions.' }
        '^Autorun executable|^Startup folder' { return 'A user with effective write access could substitute a startup program or add an entry consumed during logon. It runs in the affected logon context; user-level startup does not automatically grant administrator or SYSTEM rights.' }
        '^System PATH|^Safe DLL' { return 'A local user could plant an executable or DLL in a writable location searched before the intended file. Requires an application using that search order and loading the chosen name. Privilege gain depends on the consuming process identity.' }
        '^AlwaysInstallElevated' { return 'With both machine and current-user policies enabled, a standard user can submit an MSI whose installation actions execute with elevated Windows Installer privileges. Requires the policy to apply to that user and installation not to be blocked by other controls.' }
        '^Sensitive user right' { return 'An account holding this right may be able to bypass a specific access restriction or cross a privilege boundary, depending on the privilege and token context. Assignment alone does not prove the current user holds an enabled token privilege or has a usable abuse path.' }
        '^User Account Control' { return 'With UAC disabled, code launched by an administrator account can run without the usual consent boundary. An attacker still needs execution in that account; this does not grant a standard user administrator membership.' }
        '^Remote UAC' { return 'An attacker with a usable local administrator credential may obtain a full administrative token through supported remote management paths. Requires valid credentials, reachable services, and permissions; the setting does not reveal credentials.' }
        '^Automatic administrative logon' { return 'Physical or console access after automatic sign-in may expose the configured account session. Sensitive AutoLogon configuration can also increase credential exposure to sufficiently privileged readers. This check reads no password and does not establish the sign-in account is an administrator.' }
        '^WDigest|^LSA protection|^Reversible password' { return 'This setting can weaken protection of credentials available after authentication or in account storage. An attacker would additionally need access to the relevant privileged process or credential store and usable account material. The report neither retrieves that material nor proves it is present.' }
        '^Microsoft Defender exclusions' { return 'An attacker with a separate execution or file-write foothold may place activity within an excluded path, process, or file type to reduce inspection. Exclusion scope and remaining endpoint controls determine whether detection or blocking is actually avoided.' }
        '^Microsoft Defender real-time|^Defender script scanning|^Potentially unwanted' { return 'An attacker who can already deliver or execute content may face fewer inspection or blocking checks. This is a protection gap, not an independent execution vulnerability; other security products may provide equivalent controls.' }
        '^Windows Firewall profile|^Broad inbound firewall' { return 'A network attacker may reach services that would otherwise be filtered. Exploitation still requires a listening service, an applicable route/profile/rule, and a separate service weakness or usable credential.' }
        '^SMBv1' { return 'A reachable SMBv1 service increases exposure to weaknesses in legacy protocol implementations. Actual compromise requires an applicable unpatched flaw or authentication weakness; the enabled protocol alone does not identify a CVE.' }
        '^SMB (server|client) signing|^LDAP server signing|^LDAP channel binding|^NTLM compatibility' { return 'An attacker able to intercept or induce authentication may attempt relay or protocol-specific manipulation where effective signing, binding, or authentication restrictions allow it. Requires compatible client/target behavior and reachable services; a registry observation alone is not a demonstrated relay path.' }
        '^Insecure SMB guest|^Anonymous users|^Built-in Guest' { return 'An attacker may obtain guest or anonymous access to resources explicitly permitted to that identity. Reachability, effective share/file permissions, and logon restrictions still apply; the setting does not imply unrestricted access.' }
        '^Broad write access to SMB' { return 'A principal allowed by both share and filesystem permissions could change shared data or plant a file consumed by another user or process. Execution or elevation requires that additional consumer and its privileges; share permission alone is insufficient.' }
        '^RDP is enabled without' { return 'A reachable RDP listener exposes more pre-authentication handling without NLA. An attacker could target an applicable pre-authentication weakness or resource exhaustion, but a separate vulnerable implementation or valid credentials is still needed for access.' }
        '^Remote Desktop is enabled' { return 'A reachable RDP service provides a remote logon path to an attacker with valid credentials and logon rights. Enabling RDP alone is not an exploit and does not bypass authentication.' }
        '^WinRM TrustedHosts' { return 'A management client using a broad TrustedHosts list may connect to an unintended or impersonated endpoint under authentication configurations that do not verify server identity. Requires an administrator to initiate such a connection; this setting does not grant inbound access by itself.' }
        '^PowerShell .*Logging|^Dropped firewall|^Security event log|^Sysmon|^Command-line inclusion' { return 'An attacker with an existing foothold may leave fewer retained or detailed audit records, making investigation harder. This is a visibility/retention gap, not a direct code-execution or privilege-escalation mechanism.' }
        '^No enforced AppLocker|^Legacy PowerShell' { return 'An attacker with an existing ability to launch programs may encounter fewer application-control or modern scripting protections. Other controls, including WDAC, can still block execution. This observation alone does not grant execution privileges.' }
        '^LLMNR|^NetBIOS' { return 'An attacker on a relevant network segment may spoof name-resolution replies to redirect a client toward an attacker-controlled endpoint. Credential exposure or relay requires a client request, subsequent authentication, and insufficient signing/binding or other defenses.' }
        'server protocol is explicitly enabled' { return 'An on-path attacker may target weaknesses in an older protocol if a real service and client negotiate it with susceptible algorithms. Registry configuration alone does not prove negotiation, a downgrade, or plaintext recovery is possible.' }
        '^No installed Windows update|^Windows Update Agent' { return 'An attacker could target an applicable vulnerability left unpatched in a reachable or locally usable component. Match the installed build and missing update to a specific advisory first; patch age or update count alone is not a confirmed exploit.' }
        '^System has a pending reboot' { return 'If security updates need a reboot, vulnerable code may remain active until restart. Requires an applicable pending fix and a separate exploitable weakness; a reboot marker alone does not establish either.' }
        '^Minimum password|^Account lockout' { return 'An attacker with access to a logon interface may attempt password guessing against weak passwords or insufficient rate limiting. Actual success depends on account passwords, authentication controls, network access, and monitoring; policy values do not reveal passwords.' }
        '^Non-administrators may install Point' { return 'A non-administrator may be able to introduce a printer driver through an allowed print installation workflow. Privilege impact depends on driver trust, server restrictions, installed patches, and spooler behavior; this policy is not proof of a particular PrintNightmare CVE.' }
        '^Configured WSUS' { return 'An attacker on the update-client network path could attempt to tamper with HTTP update metadata or redirect traffic. Code execution additionally requires a compatible update/approval weakness and delivery path; update signatures and other controls still matter.' }
        '^UEFI Secure Boot' { return 'An attacker with boot-media, firmware, or suitable local access may introduce an untrusted boot component without Secure Boot verification. Disk encryption, firmware restrictions, and physical access conditions still affect feasibility.' }
        '^BitLocker' { return 'An attacker with physical disk access may read or alter offline data when encryption is absent or protection is suspended with usable key material. The protection-off state must be interpreted together with volume encryption status and other controls.' }
        '^Image File Execution Options' { return 'An attacker who can change the debugger registration or the referenced debugger program can redirect execution when the associated application starts. It runs in that launch context. An existing debugger entry can be legitimate and does not itself grant write access.' }
        '^Permanent WMI' { return 'An attacker with permission to modify a permanent subscription could arrange execution when its event filter fires. The recorded binding may instead be approved management software; its presence alone does not establish malicious content or attacker write access.' }
        '^Unattended installation' { return 'If a retained setup file contains sensitive data and an attacker can read it, that information could support further access. Only file metadata is collected here, so neither sensitive contents nor readability by an attacker is established.' }
        default { return 'No direct exploitation path is established by this observation. Review the collected evidence, effective permissions, affected identity, and required trigger before deciding whether an abuse path exists.' }
    }
}

function Get-ExecutableFromCommandLine {

    param(
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $null
    }

    $Expanded = [Environment]::ExpandEnvironmentVariables(
        $CommandLine.Trim()
    )

    if ($Expanded.StartsWith('"')) {

        if ($Expanded -match '^"([^"]+)"') {
            return $Matches[1]
        }
    }

    if ($Expanded -match '^(.+?\.(exe|com|bat|cmd|ps1|vbs|js))(\s|$)') {
        return $Matches[1].Trim()
    }

    return $null
}

function Test-UnquotedExecutablePath {

    param(
        [string]$CommandLine
    )

    if ([string]::IsNullOrWhiteSpace($CommandLine)) {
        return $false
    }

    $Expanded = [Environment]::ExpandEnvironmentVariables(
        $CommandLine.Trim()
    )

    if ($Expanded.StartsWith('"')) {
        return $false
    }

    $Exe = Get-ExecutableFromCommandLine $Expanded

    if (-not $Exe) {
        return $false
    }

    if ($Exe -notmatch "\s") {
        return $false
    }

    return $true
}

function Get-WeakAclEntries {

    param(
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return @()
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    try {

        $Acl = Get-Acl `
            -LiteralPath $Path `
            -ErrorAction Stop

        $WeakIdentities = @(
            "Everyone",
            "BUILTIN\Users",
            "NT AUTHORITY\Authenticated Users",
            "Authenticated Users",
            "Users"
        )

        $Results = @()

        foreach ($Rule in $Acl.Access) {

            $Identity = $Rule.IdentityReference.Value

            if ($WeakIdentities -notcontains $Identity) {
                continue
            }

            if ($Rule.AccessControlType -ne "Allow") {
                continue
            }

            $Rights = "$($Rule.FileSystemRights)"

            if (
                $Rights -match "FullControl" -or
                $Rights -match "Modify" -or
                $Rights -match "Write" -or
                $Rights -match "CreateFiles" -or
                $Rights -match "CreateDirectories" -or
                $Rights -match "WriteData" -or
                $Rights -match "AppendData" -or
                $Rights -match "ChangePermissions" -or
                $Rights -match "TakeOwnership"
            ) {

                $Results += [PSCustomObject]@{
                    Path      = $Path
                    Identity  = $Identity
                    Rights    = $Rights
                    Inherited = $Rule.IsInherited
                }
            }
        }

        return $Results
    }
    catch {
        Add-CollectionError "ACL: $Path" $_.Exception.Message
        return @()
    }
}

function Get-WeakRegistryAclEntries {

    param(
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        return @()
    }

    try {

        $Acl = Get-Acl `
            -Path $Path `
            -ErrorAction Stop

        $WeakIdentities = @(
            "Everyone",
            "BUILTIN\Users",
            "NT AUTHORITY\Authenticated Users",
            "Authenticated Users",
            "Users"
        )

        $Results = @()

        foreach ($Rule in $Acl.Access) {

            $Identity = $Rule.IdentityReference.Value

            if ($WeakIdentities -notcontains $Identity) {
                continue
            }

            if ($Rule.AccessControlType -ne "Allow") {
                continue
            }

            $Rights = "$($Rule.RegistryRights)"

            if (
                $Rights -match "FullControl" -or
                $Rights -match "WriteKey" -or
                $Rights -match "SetValue" -or
                $Rights -match "CreateSubKey" -or
                $Rights -match "ChangePermissions" -or
                $Rights -match "TakeOwnership"
            ) {

                $Results += [PSCustomObject]@{
                    Path      = $Path
                    Identity  = $Identity
                    Rights    = $Rights
                    Inherited = $Rule.IsInherited
                }
            }
        }

        return $Results
    }
    catch {
        Add-CollectionError "ACL: $Path" $_.Exception.Message
        return @()
    }
}

function Test-PathWritableByStandardUsers {

    param(
        [string]$Path
    )

    $Weak = Get-WeakAclEntries $Path

    return (@($Weak).Count -gt 0)
}

function Get-ServiceSddl {

    param(
        [string]$ServiceName
    )

    try {

        $Output = & sc.exe sdshow $ServiceName 2>$null

        $Sddl = (
            $Output |
            Where-Object {
                $_ -match "^D:"
            }
        )

        if ($Sddl) {
            return ($Sddl -join "")
        }
    }
    catch {}

    return $null
}

function Test-ServiceSddlWeak {

    param(
        [string]$Sddl
    )

    if ([string]::IsNullOrWhiteSpace($Sddl)) {
        return $false
    }

    try {
        $Descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($Sddl)
        foreach ($Ace in $Descriptor.DiscretionaryAcl) {
            if ($Ace -isnot [System.Security.AccessControl.CommonAce]) { continue }
            if ($Ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
            if ($Ace.SecurityIdentifier.Value -notin @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')) { continue }
            # SERVICE_CHANGE_CONFIG, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL/WRITE.
            # This identifies broad allow ACEs, not a full effective-access calculation.
            if (($Ace.AccessMask -band 0x500D0002) -ne 0) { return $true }
        }
    }
    catch {
        Add-CollectionError 'ServiceSDDL' $_.Exception.Message
    }

    return $false
}

function Get-PendingRebootStatus {

    $Reasons = @()

    if (
        Test-Path `
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    ) {

        $Reasons += "Component Based Servicing"
    }

    if (
        Test-Path `
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    ) {

        $Reasons += "Windows Update"
    }

    $PendingRename = Get-RegistryValue `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
        "PendingFileRenameOperations"

    if ($PendingRename) {

        $Reasons += "PendingFileRenameOperations"
    }

    return [PSCustomObject]@{
        Pending = (@($Reasons).Count -gt 0)
        Reasons = $Reasons
    }
}

function ConvertTo-PowerShellLiteral {
    param([string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Get-RegistryReviewCommand {
    param([string]$Path, [string[]]$Names)
    $QuotedNames = ($Names | ForEach-Object { ConvertTo-PowerShellLiteral $_ }) -join ', '
    return "Get-ItemProperty -LiteralPath $(ConvertTo-PowerShellLiteral $Path) -Name $QuotedNames | Format-List"
}

function Invoke-LocalCheck {
    param(
        [string]$Name,
        [string]$Command,
        [scriptblock]$Collect,
        [scriptblock]$Evaluate,
        [string]$RequiredCommand = ''
    )
    $Row = [PSCustomObject]@{
        Check = $Name
        Status = 'Collected'
        Command = $Command
        Evidence = $null
        Note = ''
    }
    if ($RequiredCommand -and -not (Get-Command $RequiredCommand -ErrorAction SilentlyContinue)) {
        $Row.Status = 'Unavailable'
        $Row.Note = "Required command is not installed: $RequiredCommand"
        return $Row
    }
    try {
        $ErrorActionPreference = 'Stop'
        $ErrorsBefore = @($script:Errors).Count
        $Row.Evidence = @(& $Collect)
        if ($Row.Evidence.Count -eq 0) {
            $Row.Status = 'No data'
            $Row.Note = 'No applicable objects or explicitly configured values were returned. This is not a pass.'
        }
        if (@($script:Errors).Count -gt $ErrorsBefore) {
            $Row.Status = 'Partial'
            $Row.Note = 'Some objects could not be collected. See Collection Errors.'
        }
    }
    catch {
        $Row.Status = 'Unavailable'
        $Row.Note = $_.Exception.Message
        Add-CollectionError $Name $Row.Note
        return $Row
    }
    if ($Evaluate -and $Row.Status -eq 'Collected') {
        try { & $Evaluate $Row.Evidence $Command }
        catch {
            $Row.Status = 'Evaluation failed'
            $Row.Note = $_.Exception.Message
            Add-CollectionError "$Name evaluation" $Row.Note
        }
    }
    return $Row
}

function ConvertTo-HtmlText {
    param($Value)
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-ReportValueHtml {
    param($Value)
    if ($null -eq $Value) { return '<p class="empty">Not collected or not configured.</p>' }
    if ($Value -is [System.Collections.IDictionary]) {
        return (($Value.Keys | ForEach-Object {
            '<details class="subsection"><summary>' + (ConvertTo-HtmlText $_) +
            '</summary><div class="section-body">' + (ConvertTo-ReportValueHtml $Value[$_]) + '</div></details>'
        }) -join [Environment]::NewLine)
    }
    $Items = @($Value)
    if ($Items.Count -eq 0) { return '<p class="empty">No records returned. This does not establish a passing security result.</p>' }
    $ScalarItems = @($Items | Where-Object { $null -eq $_ -or $_ -is [string] -or $_.GetType().IsValueType })
    if ($ScalarItems.Count -eq $Items.Count) {
        return '<pre class="output"><code>' + (ConvertTo-HtmlText ($Items -join [Environment]::NewLine)) + '</code></pre>'
    }
    if ($ScalarItems.Count -gt 0) {
        return '<pre class="output"><code>' + (ConvertTo-HtmlText (Convert-ToSafeString $Value)) + '</code></pre>'
    }
    $Properties = New-Object 'System.Collections.Generic.List[string]'
    foreach ($Item in $Items) {
        foreach ($Property in $Item.PSObject.Properties.Name) {
            if (-not $Properties.Contains($Property)) { $Properties.Add($Property) }
        }
    }
    $Builder = New-Object System.Text.StringBuilder
    [void]$Builder.Append('<div class="table-scroll"><table class="data-table"><thead><tr>')
    foreach ($Property in $Properties) { [void]$Builder.Append('<th>' + (ConvertTo-HtmlText $Property) + '</th>') }
    [void]$Builder.Append('</tr></thead><tbody>')
    foreach ($Item in $Items) {
        [void]$Builder.Append('<tr>')
        foreach ($Property in $Properties) {
            $Cell = $Item.$Property
            if ($null -ne $Cell -and $Cell -isnot [string] -and -not $Cell.GetType().IsValueType) {
                $Cell = Convert-ToSafeString $Cell
            }
            [void]$Builder.Append('<td><pre><code>' + (ConvertTo-HtmlText $Cell) + '</code></pre></td>')
        }
        [void]$Builder.Append('</tr>')
    }
    [void]$Builder.Append('</tbody></table></div>')
    return $Builder.ToString()
}

function Test-EvidenceIssueLine {
    param([string]$Title, [string]$Line)
    # Match values in serialized evidence, not substrings in HTML or command text.
    if ($Line -notmatch '^\s*"(?<Field>[^"]+)"\s*:\s*(?<Value>.+?)\s*,?\s*$') {
        return ($Title -match '^WinRM TrustedHosts' -and $Line.Trim() -eq '*')
    }
    $Field = $Matches.Field
    $RawValue = $Matches.Value.TrimEnd(',').Trim()
    $Value = $RawValue.Trim('"')
    switch -Regex ($Title) {        '^Installed software DLL loading candidate' {return $Field -eq 'BroadWriteAllow' -and $Value -eq 'true'}
        '^Installed software process injection access' {return $Field -in @('InjectionRightsGranted','HigherIntegrity','DifferentUser') -and $Value -eq 'true'}
        '^Unquoted service' { return ($Field -eq 'UnquotedPath' -and $Value -eq 'true') -or ($Field -eq 'PathName' -and $Value -notmatch '^\\?"') }
        '^Service executable|^Service registry|^Scheduled task .*writ|^Autorun executable|^Startup folder|^System PATH directory' {
            return $Field -eq 'Rights' -and $Value -match 'FullControl|Modify|Write|CreateFiles|CreateDirectories|AppendData|ChangePermissions|TakeOwnership'
        }
        '^Potentially broad service-object' { return $Field -eq 'BroadServiceControlRights' -and $Value -eq 'true' }
        '^Sensitive user right' { return $Field -in @('Right','Principals') }
        '^User Account Control' { return $Field -eq 'EnableLUA' -and $Value -eq '0' }
        '^Remote UAC' { return $Field -eq 'LocalAccountTokenFilterPolicy' -and $Value -eq '1' }
        '^AlwaysInstallElevated' { return $Field -in @('HKLM','HKCU') -and $Value -eq '1' }
        '^Automatic administrative logon' { return $Field -eq 'AutoAdminLogon' -and $Value -eq '1' }
        '^Microsoft Defender real-time' { return $Field -eq 'RealTimeProtectionEnabled' -and $Value -eq 'false' }
        '^Defender script scanning' { return $Field -eq 'DisableScriptScanning' -and $Value -eq 'true' }
        '^Potentially unwanted' { return $Field -eq 'PUAProtection' -and $Value -eq '0' }
        '^Microsoft Defender exclusions' { return $Field -eq 'Value' -and $RawValue -ne 'null' }
        '^Windows Firewall profile' { return $Field -eq 'Enabled' -and $Value -in @('false','0') }
        '^Dropped firewall' { return $Field -eq 'LogBlocked' -and $Value -in @('false','0') }
        '^Broad inbound firewall' { return $Field -in @('RemoteAddress','LocalPort') -and $Value -in @('Any','*') }
        '^SMBv1' { return $Field -eq 'EnableSMB1Protocol' -and $Value -eq 'true' }
        '^SMB (server|client) signing' { return $Field -eq 'RequireSecuritySignature' -and $Value -eq 'false' }
        '^Insecure SMB guest' { return $Field -eq 'EnableInsecureGuestLogons' -and $Value -eq 'true' }
        '^Broad write access to SMB' { return $Field -eq 'AccessRight' -and $Value -in @('Full','Change') }
        '^NTLM compatibility' { return $Field -eq 'LmCompatibilityLevel' -and $Value -match '^[0-4]$' }
        '^Anonymous users' { return $Field -eq 'EveryoneIncludesAnonymous' -and $Value -eq '1' }
        '^RDP is enabled without' { return $Field -eq 'NLAEnabled' -and $Value -eq 'false' }
        '^Remote Desktop' { return $Field -eq 'Enabled' -and $Value -eq 'true' }
        '^PowerShell Script Block' { return $Field -eq 'ScriptBlockLogging' -and $Value -ne '1' }
        '^PowerShell Module' { return $Field -eq 'ModuleLogging' -and $Value -ne '1' }
        '^WDigest' { return $Field -eq 'WDigestUseLogonCredential' -and $Value -eq '1' }
        '^LSA protection' { return $Field -eq 'RunAsPPL' -and $Value -notin @('1','2') }
        '^No enforced AppLocker' { return $Field -eq 'EnforcementMode' -and $Value -ne 'Enabled' }
        '^Safe DLL search' { return $Field -eq 'SafeDllSearchMode' -and $Value -eq '0' }
        '^LLMNR' { return $Field -eq 'LLMNRPolicy' -and $Value -ne '0' }
        '^NetBIOS' { return $Field -eq 'TcpipNetbiosOptions' -and $Value -ne '2' }
        'server protocol is explicitly' { return $Field -eq 'Enabled' -and $Value -eq '1' }
        '^LDAP server signing' { return $Field -eq 'LDAPServerIntegrity' -and $Value -eq '0' }
        '^LDAP channel' { return $Field -eq 'LDAPEnforceChannelBinding' -and $Value -eq '0' }
        '^Security event log' { return $Field -eq 'MaximumSizeInBytes' -and $Value -match '^\d+$' -and [double]$Value -lt 1073741824 }
        '^System has a pending reboot' { return $Field -eq 'Pending' -and $Value -eq 'true' }
        '^Windows Update Agent' { return $Field -eq 'Title' }
        '^Built-in Guest' { return $Field -eq 'Enabled' -and $Value -eq 'true' }
        '^Minimum password' { return $Field -eq 'MinimumPasswordLength' -and $Value -match '^\d+$' -and [int]$Value -lt 14 }
        '^Reversible password' { return $Field -eq 'ClearTextPassword' -and $Value -eq '1' }
        '^Account lockout' { return $Field -eq 'LockoutBadCount' -and $Value -eq '0' }
        '^Non-administrators may install' { return $Field -eq 'RestrictDriverInstallationToAdministrators' -and $Value -eq '0' }
        '^Configured WSUS' { return $Field -eq 'WUServer' -and $Value -match '^http://' }
        '^UEFI Secure Boot' { return $Field -eq 'Enabled' -and $Value -eq 'false' }
        '^BitLocker' { return $Field -eq 'ProtectionStatus' -and $Value -in @('Off','0') }
        '^Legacy PowerShell' { return $Field -eq 'State' -and $Value -in @('Enabled','2') }
        '^Command-line inclusion' { return $Field -eq 'ProcessCreationIncludeCmdLine_Enabled' -and $Value -eq '0' }
        '^Image File Execution Options' { return $Field -eq 'Debugger' -and $RawValue -ne 'null' }
        '^Permanent WMI' { return $Field -in @('Filter','Consumer') }
        '^Unattended installation' { return $Field -eq 'FullName' }
        default { return $false }
    }
}

function ConvertTo-FindingEvidenceHtml {
    param($Finding)
    $Builder = New-Object System.Text.StringBuilder
    [void]$Builder.Append('<div class="terminal-label">Command and collected response</div><pre class="output evidence-session"><code>')
    $CommandLines = [regex]::Split([string]$Finding.Command, '\r\n|\n|\r')
    for ($i = 0; $i -lt $CommandLines.Count; $i++) {
        $Prompt = if ($i -eq 0) { 'PS&gt; ' } else { '&gt;&gt; ' }
        [void]$Builder.Append('<span class="evidence-command">' + $Prompt +
            (ConvertTo-HtmlText $CommandLines[$i]) + '</span>' + [Environment]::NewLine)
    }
    [void]$Builder.Append([Environment]::NewLine + '<span class="response-label">Collected response (selected fields)</span>' + [Environment]::NewLine)
    $Highlighted = $false
    $ArrayField = ''
    foreach ($Line in [regex]::Split([string]$Finding.Evidence, '\r\n|\n|\r')) {
        $Encoded = ConvertTo-HtmlText $Line
        if ($Line -match '^\s*"(?<Field>RemoteAddress|LocalPort)"\s*:\s*\[') { $ArrayField = $Matches.Field }
        elseif ($Line -match '^\s*\]') { $ArrayField = '' }
        $IssueLine = Test-EvidenceIssueLine -Title $Finding.Finding -Line $Line
        if ($ArrayField -and $Line.Trim().TrimEnd(',') -in @('"Any"','"*"')) {
            $IssueLine = Test-EvidenceIssueLine -Title $Finding.Finding -Line ('"' + $ArrayField + '": ' + $Line.Trim())
        }
        if ($IssueLine) {
            [void]$Builder.Append('<mark class="issue-highlight" title="Evidence relevant to this finding">' + $Encoded + '</mark>')
            $Highlighted = $true
        }
        else { [void]$Builder.Append($Encoded) }
        [void]$Builder.Append([Environment]::NewLine)
    }
    [void]$Builder.Append('</code></pre>')
    if ($Finding.EvidenceSummary) {
        # Absence/age findings may have no single raw field that represents the trigger.
        $Class = if ($Highlighted) { 'evidence-observation' } else { 'evidence-observation issue-observation' }
        [void]$Builder.Append('<div class="' + $Class + '"><strong>Assessment observation:</strong><pre>' +
            (ConvertTo-HtmlText $Finding.EvidenceSummary) + '</pre></div>')
    }
    return $Builder.ToString()
}

function New-AssessmentText {
    param([System.Collections.IDictionary]$Report)
    $Parts = @('WINDOWS HOST SECURITY ASSESSMENT', 'Full selected collection data; no table-format truncation.')
    foreach ($Key in $Report.Keys) {
        $Parts += [Environment]::NewLine + ('=' * 78) + [Environment]::NewLine + $Key
        $Parts += Convert-ToSafeString $Report[$Key]
    }
    return $Parts -join [Environment]::NewLine
}

function ConvertTo-VerificationResultHtml {
    param($Result, [string]$Title)
    if ($null -eq $Result) { return '<p class="hint">Verification has not been executed.</p>' }
    $Builder = New-Object System.Text.StringBuilder
    [void]$Builder.Append('<div class="verification-result"><strong>Executed verification: ' + (ConvertTo-HtmlText $Result.Status) + '</strong><p>' + (ConvertTo-HtmlText $Result.Explanation) + '</p>')
    if ($Result.ExecutionContext) {
        [void]$Builder.Append('<p class="hint">' + (ConvertTo-HtmlText ($Result.ExecutionContext.Host + ' | ' + $Result.ExecutionContext.User + ' | Elevated: ' + $Result.ExecutionContext.IsAdministrator)) + '</p>')
    }
    foreach ($Step in @($Result.Steps)) {
        [void]$Builder.Append('<details class="verification-transcript"><summary>' + (ConvertTo-HtmlText ($Step.Name + ' - ' + $Step.Status)) + '</summary><div class="verification-body"><p>' + (ConvertTo-HtmlText $Step.Explanation) + '</p><p class="hint">' + (ConvertTo-HtmlText ('{0} | {1} ms' -f $Step.StartedAt,$Step.DurationMilliseconds)) + '</p>')
        [void]$Builder.Append('<div class="terminal-label">Executed command</div><pre class="command"><code>' + (ConvertTo-HtmlText $Step.Command) + '</code></pre><button type="button" class="copy-command">Copy command</button>')
        [void]$Builder.Append('<div class="terminal-label">Complete captured response (selected fields)</div><pre class="output"><code>')
        if ([string]::IsNullOrEmpty([string]$Step.Output)) { [void]$Builder.Append('(No success-stream output)') }
        $BroadRule = $false
        foreach ($Line in [regex]::Split([string]$Step.Output, '\r\n|\n|\r')) {
            $Encoded = ConvertTo-HtmlText $Line
            if ($Line -match '"BroadWriteAllow"\s*:\s*(true|false)') { $BroadRule = $Matches[1] -eq 'true' }
            $IssueLine = Test-EvidenceIssueLine -Title $Title -Line $Line
            if ($Line -match '^\s*"Rights"\s*:') { $IssueLine = $BroadRule }
            if ($IssueLine -or $Line -match '"(WriteOpenSucceeded|BroadWriteAllow)"\s*:\s*true') {
                $Encoded = '<mark class="issue-highlight">' + $Encoded + '</mark>'
            }
            [void]$Builder.Append($Encoded + [Environment]::NewLine)
        }
        [void]$Builder.Append('</code></pre>')
        foreach ($Stream in @('Errors','Warnings','Information','Verbose','Debug')) {
            if (@($Step.$Stream).Count) {
                [void]$Builder.Append('<div class="terminal-label">' + $Stream + '</div><pre class="output"><code>' + (ConvertTo-HtmlText (Convert-ToSafeString $Step.$Stream)) + '</code></pre>')
            }
        }
        if ($Step.Failure) { [void]$Builder.Append('<p class="issue-observation">' + (ConvertTo-HtmlText $Step.Failure) + '</p>') }
        [void]$Builder.Append('</div></details>')
    }
    [void]$Builder.Append('</div>')
    return $Builder.ToString()
}

function New-AssessmentHtml {
    param([System.Collections.IDictionary]$Report, [string]$Title='Host Security Report', [string]$ReportLink='', [string]$LinkLabel='DLL injection / sideloading analysis')
    $Ranks = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
    $SortedFindings = @($Report.Findings | Sort-Object @{Expression={$Ranks[$_.Severity]}},Category,Finding)
    $Rows = New-Object System.Text.StringBuilder
    foreach ($Finding in $SortedFindings) {
        $Rank = $Ranks[$Finding.Severity]
        [void]$Rows.Append('<tr data-severity="' + $Rank + '">')
        [void]$Rows.Append('<td><span class="severity severity-' + $Rank + '">' + (ConvertTo-HtmlText $Finding.Severity) + '</span></td>')
        foreach ($Field in @('Category','Finding','Status')) {
            [void]$Rows.Append('<td>' + (ConvertTo-HtmlText $Finding.$Field) + '</td>')
        }
        [void]$Rows.Append('<td class="command-cell"><div class="terminal-label">PowerShell command</div><pre class="command"><code>' +
            (ConvertTo-HtmlText $Finding.Command) + '</code></pre><button type="button" class="copy-command">Copy command</button></td>')
        [void]$Rows.Append('<td class="evidence-cell">' + (ConvertTo-FindingEvidenceHtml $Finding) + '</td>')
        [void]$Rows.Append('<td class="exploit-cell">' + (ConvertTo-HtmlText $Finding.HowToExploit) + '</td>')
        $StepsProperty = $Finding.PSObject.Properties['VerificationSteps']
        $Steps = if ($null -ne $StepsProperty) { [string]$StepsProperty.Value } else { '' }
        if ([string]::IsNullOrWhiteSpace($Steps)) {
            $Steps = Get-FindingVerificationSteps -Title $Finding.Finding -Category $Finding.Category -EvidenceData $Finding.EvidenceData -Command $Finding.Command
        }
        $ResultProperty = $Finding.PSObject.Properties['VerificationResult']
        $Result = if ($null -ne $ResultProperty) { $ResultProperty.Value } else { $null }
        $ResultHtml = ConvertTo-VerificationResultHtml -Result $Result -Title $Finding.Finding
        if ([string]::IsNullOrWhiteSpace($Steps)) {
            [void]$Rows.Append('<td class="verification-cell"><span class="hint">No additional privilege-escalation steps for this finding.</span>' + $ResultHtml + '</td>')
        } else {
            [void]$Rows.Append('<td class="verification-cell"><details><summary>Verification commands</summary><div class="verification-body"><div class="terminal-label">Next verification steps</div><pre class="command"><code>' +
                (ConvertTo-HtmlText $Steps) + '</code></pre><button type="button" class="copy-command">Copy steps</button></div></details>' + $ResultHtml + '</td>')
        }
        [void]$Rows.Append('<td>' + (ConvertTo-HtmlText $Finding.Recommendation))
        if ($Finding.Reference -match '^https?://') {
            [void]$Rows.Append('<p><a target="_blank" rel="noopener noreferrer" href="' +
                (ConvertTo-HtmlText $Finding.Reference) + '">Reference</a></p>')
        }
        [void]$Rows.Append('</td></tr>')
    }
    $Sections = New-Object System.Text.StringBuilder
    $Navigation = New-Object System.Text.StringBuilder
    $SectionId = 0
    foreach ($Key in $Report.Keys) {
        if ($Key -in @('Metadata','Findings','SeveritySummary')) { continue }
        $SectionId++
        $Title = [regex]::Replace($Key, '([a-z])([A-Z])', '$1 $2')
        [void]$Navigation.Append('<a href="#section-' + $SectionId + '">' + (ConvertTo-HtmlText $Title) + '</a>')
        [void]$Sections.Append('<details class="report-section" id="section-' + $SectionId + '"><summary>' +
            (ConvertTo-HtmlText $Title) + '</summary><div class="section-body">' +
            (ConvertTo-ReportValueHtml $Report[$Key]) + '</div></details>')
    }
    $Cards = (@('Critical','High','Medium','Low','Informational') | ForEach-Object {
        '<div class="stat"><span class="severity severity-' + $Ranks[$_] + '">' + $_ +
        '</span><strong>' + (ConvertTo-HtmlText $Report.SeveritySummary.$_) + '</strong></div>'
    }) -join ''
    $Style = @'
<style>
:root{color-scheme:light;--ink:#172b4d;--muted:#526174;--border:#dbe3ed;--surface:#fff}
*{box-sizing:border-box}body{margin:0;background:#f2f5f9;color:var(--ink);font:14px/1.55 "Segoe UI",Arial,sans-serif}
main{max-width:1800px;margin:auto;padding:32px}header{background:#14263f;color:white;border-radius:14px;padding:28px 32px}
h1{font-size:28px;line-height:1.2;margin:6px 0 16px}.eyebrow{font-size:12px;letter-spacing:.14em;color:#94c8ff;text-transform:uppercase}
.metadata{display:flex;gap:12px 28px;flex-wrap:wrap;color:#d9e7f7}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin:20px 0}
.stat{background:white;padding:16px 20px;border:1px solid var(--border);border-radius:10px}.stat strong{display:block;font-size:30px}
.severity{display:inline-block;font-size:12px;font-weight:700;border-radius:20px;padding:4px 10px;white-space:nowrap}
.severity-0{background:#5b112a;color:white}.severity-1{background:#ffe0e0;color:#9c2020}.severity-2{background:#fff0c2;color:#734800}
.severity-3{background:#dbeafe;color:#194b8c}.severity-4{background:#e9edf3;color:#42516a}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:18px 0}.toolbar label{font-weight:600}
input{padding:9px 12px;border:1px solid #adbace;border-radius:6px;min-width:240px;font:inherit}
button{font:inherit;cursor:pointer;border:1px solid #afbdce;background:white;color:var(--ink);padding:7px 12px;border-radius:6px}
button:hover{background:#eaf2ff}button:focus-visible,summary:focus-visible,a:focus-visible{outline:3px solid #2878d4;outline-offset:3px}
.report-section{background:white;border:1px solid var(--border);border-radius:10px;margin:14px 0;overflow:hidden}
summary{cursor:pointer;font-weight:650;font-size:17px;padding:16px 20px;background:#f9fbfe}
.subsection{border:1px solid var(--border);border-radius:6px;margin:10px 0;overflow:hidden}.subsection summary{font-size:14px;padding:12px 16px}
.section-body{padding:16px 20px}.hint,.empty{color:var(--muted)}nav{display:flex;flex-wrap:wrap;gap:8px 16px;margin:16px 0}a{color:#175cad}
.table-scroll{overflow:auto;max-width:100%}table{border-collapse:collapse;width:100%;text-align:left}
th,td{padding:12px;vertical-align:top;border-bottom:1px solid var(--border)}th{background:#eaf0f8;font-size:12px;white-space:nowrap}
th button{font-weight:700;font-size:12px;padding:4px;background:transparent;border:0;text-align:left}
th[aria-sort="ascending"] button::after{content:" ▲"}th[aria-sort="descending"] button::after{content:" ▼"}
tbody tr:hover{background:#f8fbff}#findings-table{min-width:2050px}#findings-table td:nth-child(3){min-width:210px}
#findings-table td:last-child{min-width:220px}.command-cell,.evidence-cell{min-width:280px;max-width:440px}
pre{margin:0;font:12px/1.6 Consolas,"Cascadia Code",monospace;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:4}
pre.command,pre.output{background:#112238;color:#e3edf8;border:1px solid #263d59;border-radius:0 0 6px 6px;padding:12px;max-height:340px;overflow:auto}
pre.command{color:#a5e9c5}.terminal-label{background:#233951;color:#c4d7ec;font:11px/1.5 "Segoe UI",sans-serif;padding:6px 12px;border-radius:6px 6px 0 0}
.evidence-command{color:#a5e9c5}.response-label{color:#b9cce1;font-weight:700}
.issue-highlight{background:#4b202d;color:#ffb4b4;font-weight:700;border-left:3px solid #ff7373;padding:1px 4px;box-decoration-break:clone;-webkit-box-decoration-break:clone}
.evidence-observation{margin-top:10px;padding:9px 12px;background:#f2f5f9;border-radius:5px}
.issue-observation{color:#a31525;border-left:3px solid #c92a3e;background:#fff1f2}
@media print{.issue-highlight{color:#a31525;background:#fff1f2;border-color:#a31525}.evidence-command,.response-label{color:#172b4d}}
.copy-command{font-size:12px;margin-top:7px}.data-table pre{overflow:auto;min-width:100px}.evidence-cell pre.output{max-height:none}.exploit-cell{min-width:280px;max-width:400px;white-space:pre-wrap}
.verification-cell{min-width:300px;max-width:480px}.verification-cell summary{font-size:13px;padding:9px 12px;border:1px solid var(--border);border-radius:6px}.verification-body{padding-top:8px}.verification-cell pre{max-height:420px}
.verification-result{margin-top:12px;border-top:1px solid var(--border);padding-top:10px}.verification-transcript{margin-top:10px}.verification-result pre.output{max-height:none}.verification-result .terminal-label{margin-top:8px}
#finding-count{color:var(--muted);margin-left:auto}.notice{border-left:3px solid #5c8dc8;padding-left:12px;color:var(--muted)}
@media(max-width:760px){main{padding:14px}header{padding:20px}h1{font-size:23px}.stats{grid-template-columns:repeat(2,1fr)}input{min-width:170px}}
@media print{.toolbar,nav,.copy-command{display:none}main{padding:0}header{background:white;color:black}.metadata{color:black}.table-scroll{overflow:visible}#findings-table{min-width:0}pre.command,pre.output{max-height:none;background:#fff;color:#000}.report-section{break-inside:auto}}
</style>
'@
    $Script = @'
<script>
(() => {
  'use strict';
  const table = document.getElementById('findings-table');
  const body = table.tBodies[0];
  const headers = Array.from(table.tHead.rows[0].cells);
  let sortColumn = 0, ascending = true;
  const rows = () => Array.from(body.rows);
  const count = () => {
    const visible = rows().filter(r => !r.hidden).length;
    document.getElementById('finding-count').textContent = visible + ' of ' + rows().length + ' findings';
  };
  function sort(index, direction) {
    sortColumn = index; ascending = direction;
    rows().sort((a, b) => {
      const x = index === 0 ? Number(a.dataset.severity) : a.cells[index].textContent.trim();
      const y = index === 0 ? Number(b.dataset.severity) : b.cells[index].textContent.trim();
      const result = index === 0 ? x - y : x.localeCompare(y, undefined, {numeric:true, sensitivity:'base'});
      return direction ? result : -result;
    }).forEach(row => body.appendChild(row));
    headers.forEach((header, i) => header.setAttribute('aria-sort', i === index ? (direction ? 'ascending' : 'descending') : 'none'));
  }
  headers.forEach((header, i) => header.querySelector('button').addEventListener('click', () => sort(i, i === sortColumn ? !ascending : true)));
  document.getElementById('finding-search').addEventListener('input', event => {
    const query = event.target.value.trim().toLowerCase();
    rows().forEach(row => row.hidden = !row.textContent.toLowerCase().includes(query));
    count();
  });
  document.getElementById('expand-all').addEventListener('click', () => document.querySelectorAll('details').forEach(d => d.open = true));
  document.getElementById('collapse-all').addEventListener('click', () => document.querySelectorAll('details').forEach(d => d.open = false));
  document.querySelectorAll('nav a').forEach(link => link.addEventListener('click', () => {
    const section = document.querySelector(link.getAttribute('href'));
    if (section) section.open = true;
  }));
  document.querySelectorAll('.copy-command').forEach(button => button.addEventListener('click', async () => {
    const code = button.parentElement.querySelector('code');
    try {
      if (!navigator.clipboard) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(code.textContent);
      button.textContent = 'Copied';
    } catch (_) {
      const selection = window.getSelection(), range = document.createRange();
      range.selectNodeContents(code); selection.removeAllRanges(); selection.addRange(range);
      button.textContent = 'Selected - press Ctrl+C';
    }
  }));
  let printState;
  window.addEventListener('beforeprint', () => {
    printState = Array.from(document.querySelectorAll('details'), d => [d, d.open]);
    printState.forEach(([d]) => d.open = true);
  });
  window.addEventListener('afterprint', () => {
    if (printState) printState.forEach(([d, open]) => d.open = open);
  });
  sort(0, true); count();
})();
</script>
'@
    $HostText = ConvertTo-HtmlText $Report.Metadata.Host
    $UserText = ConvertTo-HtmlText $Report.Metadata.CurrentUser
    $StartedText = ConvertTo-HtmlText $Report.Metadata.AssessmentStarted
    $ElevatedText = ConvertTo-HtmlText $Report.Metadata.Elevated
    $TitleText = ConvertTo-HtmlText $Title
    $RelatedLink = if ($ReportLink) {'<p class="notice"><a href="'+(ConvertTo-HtmlText $ReportLink)+'">'+(ConvertTo-HtmlText $LinkLabel)+'</a></p>'} else {''}
    return @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>$TitleText - $HostText</title>$Style</head>
<body><main><header><div class="eyebrow">Local Windows security assessment</div>
<h1>$TitleText</h1><div class="metadata"><span>Host: <b>$HostText</b></span><span>User: $UserText</span>
<span>Started: $StartedText</span><span>Elevated: $ElevatedText</span></div></header>
<div class="stats">$Cards</div>$RelatedLink
<p class="notice">Findings are configuration observations requiring context. Missing data is not a pass.
Commands rerun the relevant collection in PowerShell; results may change with time, permissions, and user context.
Evidence contains all fields and records selected by the collectors, without table-display truncation. It is not a transcript of rerunning commands. Abuse scenarios describe prerequisites, not confirmed exploitation.</p>
<p class="hint">Each evidence cell pairs the repeatable collection command with the saved response. Red marks the relevant values or assessment observation, including review items; it does not prove exploitation.</p>
<div class="toolbar"><button type="button" id="expand-all">Expand all sections</button><button type="button" id="collapse-all">Collapse all sections</button></div>
<nav aria-label="Report sections"><a href="#findings">Security findings</a>$Navigation</nav>
<details class="report-section" id="findings" open><summary>Security findings ($($SortedFindings.Count))</summary><div class="section-body">
<div class="toolbar"><label for="finding-search">Filter findings</label><input type="search" id="finding-search" placeholder="Search any column"><span id="finding-count" role="status"></span></div>
<p class="hint">Click any column heading to sort. Default: Critical, High, Medium, Low, Informational.</p>
<div class="table-scroll"><table id="findings-table"><thead><tr>
<th scope="col" aria-sort="ascending"><button type="button">Severity</button></th>
<th scope="col" aria-sort="none"><button type="button">Category</button></th>
<th scope="col" aria-sort="none"><button type="button">Finding</button></th>
<th scope="col" aria-sort="none"><button type="button">Status</button></th>
<th scope="col" aria-sort="none"><button type="button">Command</button></th>
<th scope="col" aria-sort="none"><button type="button">Evidence</button></th>
<th scope="col" aria-sort="none"><button type="button">How to exploit</button></th>
<th scope="col" aria-sort="none"><button type="button">Next verification steps</button></th>
<th scope="col" aria-sort="none"><button type="button">Recommendation</button></th>
</tr></thead><tbody>$Rows</tbody></table></div></div></details>
$Sections
<footer class="hint">Generated locally. No external scripts, fonts, or stylesheets are required.</footer>
</main>$Script</body></html>
"@
}

function Get-AdditionalHostChecks {
    # Only local configuration/metadata is collected. No credential contents or remote discovery.
    $PrintPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
    Invoke-LocalCheck -Name 'Point and Print policy' -Command (Get-RegistryReviewCommand $PrintPath @('RestrictDriverInstallationToAdministrators','NoWarningNoElevationOnInstall','UpdatePromptSettings')) -Collect {
        if (Test-Path -LiteralPath $PrintPath) {
            Get-ItemProperty -LiteralPath $PrintPath |
                Select-Object RestrictDriverInstallationToAdministrators,NoWarningNoElevationOnInstall,UpdatePromptSettings
        }
    } -Evaluate {
        param($Data, $Command)
        if ($Data[0].RestrictDriverInstallationToAdministrators -eq 0) {
            Add-Finding 'High' 'Print Security' 'Non-administrators may install Point and Print drivers' 'Review' (Convert-ToSafeString $Data) 'Require administrator privileges for driver installation and review print-service requirements.' -Command $Command -Reference 'https://support.microsoft.com/help/5005652' -EvidenceData ($Data)
        }
    }

    $WuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $WsusCommand = (Get-RegistryReviewCommand $WuPath @('WUServer','WUStatusServer')) + [Environment]::NewLine +
        (Get-RegistryReviewCommand "$WuPath\AU" @('UseWUServer'))
    Invoke-LocalCheck -Name 'WSUS transport policy' -Command $WsusCommand -Collect {
        if (Test-Path -LiteralPath $WuPath) {
            $Wu = Get-ItemProperty -LiteralPath $WuPath
            $UseWsus = $null
            if (Test-Path -LiteralPath "$WuPath\AU") { $UseWsus = (Get-ItemProperty -LiteralPath "$WuPath\AU").UseWUServer }
            [PSCustomObject]@{ WUServer=$Wu.WUServer; WUStatusServer=$Wu.WUStatusServer; UseWUServer=$UseWsus }
        }
    } -Evaluate {
        param($Data, $Command)
        if ($Data[0].UseWUServer -eq 1 -and $Data[0].WUServer -match '^http://') {
            Add-Finding 'Medium' 'Patch Management' 'Configured WSUS update service uses HTTP' 'Review' (Convert-ToSafeString $Data) 'Review WSUS TLS configuration and policy. HTTP configuration alone does not establish exploitability.' -Command $Command -EvidenceData ($Data)
        }
    }

    $LapsPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Policies\LAPS',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config',
        'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd'
    )
    $LapsNames = @('BackupDirectory','PasswordLength','PasswordAgeDays','ADPasswordEncryptionEnabled','AdmPwdEnabled')
    $LapsCommand = ($LapsPaths | ForEach-Object { Get-RegistryReviewCommand $_ $LapsNames }) -join [Environment]::NewLine
    Invoke-LocalCheck -Name 'Windows and legacy LAPS policy indicators' -Command $LapsCommand -Collect {
        foreach ($Path in $LapsPaths) {
            if (Test-Path -LiteralPath $Path) {
                $Policy = Get-ItemProperty -LiteralPath $Path
                [PSCustomObject]@{
                    Path=$Path; BackupDirectory=$Policy.BackupDirectory
                    PasswordLength=$Policy.PasswordLength; PasswordAgeDays=$Policy.PasswordAgeDays
                    ADPasswordEncryptionEnabled=$Policy.ADPasswordEncryptionEnabled
                    LegacyAdmPwdEnabled=$Policy.AdmPwdEnabled
                }
            }
        }
    }

    Invoke-LocalCheck -Name 'Secure Boot' -RequiredCommand 'Confirm-SecureBootUEFI' -Command 'Confirm-SecureBootUEFI' -Collect {
        [PSCustomObject]@{ Enabled = Confirm-SecureBootUEFI -ErrorAction Stop }
    } -Evaluate {
        param($Data, $Command)
        if ($Data[0].Enabled -eq $false) {
            Add-Finding 'Medium' 'Boot Security' 'UEFI Secure Boot is disabled' 'Review' 'Confirm-SecureBootUEFI returned False.' 'Enable Secure Boot after confirming firmware, bootloader, and recovery compatibility.' -Command $Command -EvidenceData ($Data)
        }
    }
    Invoke-LocalCheck -Name 'BitLocker volume protection' -RequiredCommand 'Get-BitLockerVolume' -Command 'Get-BitLockerVolume | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod' -Collect {
        Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod
    } -Evaluate {
        param($Data, $Command)
        foreach ($Volume in $Data) {
            if ($Volume.VolumeType -eq 'OperatingSystem' -and "$($Volume.ProtectionStatus)" -in @('Off','0')) {
                Add-Finding 'Medium' 'Disk Encryption' "BitLocker protection is off on OS volume $($Volume.MountPoint)" 'Review' (Convert-ToSafeString $Volume) 'Review OS volume encryption and suspended protectors against the physical-security baseline.' -Command $Command -EvidenceData ($Volume)
            }
        }
    }
    Invoke-LocalCheck -Name 'PowerShell optional features' -RequiredCommand 'Get-WindowsOptionalFeature' -Command "Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like '*PowerShell*' | Select-Object FeatureName,State" -Collect {
        Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object FeatureName -like '*PowerShell*' | Select-Object FeatureName,State
    } -Evaluate {
        param($Data, $Command)
        foreach ($Feature in $Data) {
            if ($Feature.FeatureName -match 'PowerShellV2' -and $Feature.State -eq 'Enabled') {
                Add-Finding 'Medium' 'Application Control' "Legacy PowerShell v2 feature enabled: $($Feature.FeatureName)" 'Review' (Convert-ToSafeString $Feature) 'Remove the legacy engine after validating application dependencies.' -Command $Command -EvidenceData ($Feature)
            }
        }
    }
    $WefPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
    Invoke-LocalCheck -Name 'Windows Event Forwarding policy' -Command "Get-ItemProperty -LiteralPath $(ConvertTo-PowerShellLiteral $WefPath) | Format-List" -Collect {
        if (Test-Path -LiteralPath $WefPath) {
            (Get-ItemProperty -LiteralPath $WefPath).PSObject.Properties |
                Where-Object Name -notmatch '^PS' | Select-Object Name,Value
        }
    }
    $AuditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    Invoke-LocalCheck -Name 'Process command-line audit policy' -Command (Get-RegistryReviewCommand $AuditPath @('ProcessCreationIncludeCmdLine_Enabled')) -Collect {
        if (Test-Path -LiteralPath $AuditPath) {
            Get-ItemProperty -LiteralPath $AuditPath | Select-Object ProcessCreationIncludeCmdLine_Enabled
        }
    } -Evaluate {
        param($Data, $Command)
        if ($Data[0].ProcessCreationIncludeCmdLine_Enabled -eq 0) {
            Add-Finding 'Low' 'Logging' 'Command-line inclusion in process-creation audit events is explicitly disabled' 'Review' 'ProcessCreationIncludeCmdLine_Enabled=0' 'Review command-line audit requirements alongside advanced process-creation auditing and protection of sensitive log contents.' -Command $Command -EvidenceData ($Data)
        }
    }

    $IfeoPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    )
    $IfeoCommand = ($IfeoPaths | ForEach-Object {
        "Get-ChildItem -LiteralPath $(ConvertTo-PowerShellLiteral $_) -Recurse | Get-ItemProperty | Where-Object Debugger | Select-Object PSPath,Debugger"
    }) -join [Environment]::NewLine
    Invoke-LocalCheck -Name 'Image File Execution Options debuggers' -Command $IfeoCommand -Collect {
        foreach ($Path in $IfeoPaths) {
            if (Test-Path -LiteralPath $Path) {
                Get-ChildItem -LiteralPath $Path -Recurse | Get-ItemProperty |
                    Where-Object Debugger | Select-Object PSPath,Debugger
            }
        }
    } -Evaluate {
        param($Data, $Command)
        Add-Finding 'Medium' 'Persistence Review' 'Image File Execution Options debugger redirects are configured' 'Review' (Convert-ToSafeString $Data) 'Confirm each debugger registration is approved. Legitimate development and diagnostic tools also use these entries.' -Command $Command -Reference 'https://www.ired.team/offensive-security/privilege-escalation/t1183-image-file-execution-options-injection' -EvidenceData ($Data)
    }
    Invoke-LocalCheck -Name 'Permanent WMI subscription bindings' -Command 'Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Select-Object Filter,Consumer' -Collect {
        Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | Select-Object Filter,Consumer
    } -Evaluate {
        param($Data, $Command)
        Add-Finding 'Informational' 'Persistence Review' 'Permanent WMI event subscriptions are registered' 'Review' (Convert-ToSafeString $Data) 'Validate filter and consumer ownership against approved management software. Registration alone is not evidence of compromise.' -Command $Command -EvidenceData ($Data)
    }
    $StartupPaths = @(
        [Environment]::GetFolderPath('CommonStartup'),
        [Environment]::GetFolderPath('Startup')
    ) | Where-Object { $_ }
    $StartupCommand = ($StartupPaths | ForEach-Object {
        "Get-Item -LiteralPath $(ConvertTo-PowerShellLiteral $_); Get-ChildItem -LiteralPath $(ConvertTo-PowerShellLiteral $_) -Force; (Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $_)).Access | Format-Table -Wrap"
    }) -join [Environment]::NewLine
    Invoke-LocalCheck -Name 'Startup folders and broad write permissions' -Command $StartupCommand -Collect {
        foreach ($Path in $StartupPaths) {
            if (Test-Path -LiteralPath $Path) {
                [PSCustomObject]@{
                    Path=$Path
                    Items=@(Get-ChildItem -LiteralPath $Path -Force | Select-Object Name,FullName,Length,LastWriteTime)
                    BroadWriteAces=@(Get-WeakAclEntries $Path)
                }
            }
        }
    } -Evaluate {
        param($Data, $Command)
        foreach ($Folder in $Data) {
            if (@($Folder.BroadWriteAces).Count -gt 0) {
                Add-Finding 'Medium' 'Persistence Review' "Startup folder has broad write permissions: $($Folder.Path)" 'Review' (Convert-ToSafeString $Folder.BroadWriteAces) 'Review broad allow ACEs and effective permissions, especially for the all-users startup folder.' -Command $Command -EvidenceData ($Folder)
            }
        }
    }
    $UnattendPaths = @(
        "$env:SystemRoot\Panther\Unattend.xml",
        "$env:SystemRoot\Panther\Unattended.xml",
        "$env:SystemRoot\Panther\Unattend\Unattend.xml",
        "$env:SystemRoot\Panther\Unattend\Unattended.xml",
        "$env:SystemRoot\System32\Sysprep\unattend.xml",
        "$env:SystemRoot\System32\Sysprep\unattended.xml",
        "$env:SystemRoot\sysprep\sysprep.xml",
        "$env:SystemRoot\sysprep\sysprep.inf",
        "$env:SystemDrive\unattend.xml"
    )
    $UnattendCommand = ($UnattendPaths | ForEach-Object {
        "Get-Item -LiteralPath $(ConvertTo-PowerShellLiteral $_) | Select-Object FullName,Length,LastWriteTime"
    }) -join [Environment]::NewLine
    Invoke-LocalCheck -Name 'Unattended setup file metadata' -Command $UnattendCommand -Collect {
        foreach ($Path in $UnattendPaths) {
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                Get-Item -LiteralPath $Path | Select-Object FullName,Length,LastWriteTime
            }
        }
    } -Evaluate {
        param($Data, $Command)
        Add-Finding 'Informational' 'Deployment Artifacts' 'Unattended installation files remain on disk' 'Review' (Convert-ToSafeString $Data) 'Review retention and access permissions. Only metadata was collected; the files were not inspected for credentials.' -Command $Command -EvidenceData ($Data)
    }
    Invoke-LocalCheck -Name 'Local group memberships' -RequiredCommand 'Get-LocalGroup' -Command 'Get-LocalGroup | ForEach-Object { $g = $_; Get-LocalGroupMember -Group $g.Name | Select-Object @{Name="Group";Expression={$g.Name}},Name,ObjectClass,PrincipalSource }' -Collect {
        foreach ($Group in Get-LocalGroup) {
            try {
                Get-LocalGroupMember -Group $Group.Name -ErrorAction Stop |
                    Select-Object @{Name='Group';Expression={$Group.Name}},Name,ObjectClass,PrincipalSource
            }
            catch { Add-CollectionError "Local group: $($Group.Name)" $_.Exception.Message }
        }
    }
    Invoke-LocalCheck -Name 'Established TCP connections' -RequiredCommand 'Get-NetTCPConnection' -Command "Get-NetTCPConnection | Where-Object State -eq 'Established' | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess" -Collect {
        Get-NetTCPConnection | Where-Object State -eq 'Established' | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess
    }
    Invoke-LocalCheck -Name 'Neighbor cache' -RequiredCommand 'Get-NetNeighbor' -Command 'Get-NetNeighbor | Select-Object InterfaceIndex,IPAddress,LinkLayerAddress,State' -Collect {
        Get-NetNeighbor | Select-Object InterfaceIndex,IPAddress,LinkLayerAddress,State
    }
    Invoke-LocalCheck -Name 'DNS client cache' -RequiredCommand 'Get-DnsClientCache' -Command 'Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,Data,TimeToLive' -Collect {
        Get-DnsClientCache | Select-Object Entry,RecordName,RecordType,Data,TimeToLive
    }
    Invoke-LocalCheck -Name 'Mapped network drives' -Command 'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=4" | Select-Object DeviceID,ProviderName,VolumeName' -Collect {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=4' | Select-Object DeviceID,ProviderName,VolumeName
    }
    Invoke-LocalCheck -Name 'Registered antivirus products (client Windows)' -Command 'Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState,timestamp' -Collect {
        Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
            Select-Object displayName,productState,timestamp
    }
}


function New-VerificationStep {
    param([string]$Name, [string]$Command, [string]$Explanation)
    [pscustomobject]@{Name=$Name;Command=$Command;Explanation=$Explanation}
}

function Get-LocalVerificationPlan {
    param($Finding)
    $Steps=New-Object 'System.Collections.Generic.List[object]'
    $Title=[string]$Finding.Finding
    $Data=$Finding.EvidenceData
    if ($Title -match '^Installed software DLL loading candidate|^Installed software process injection access') {
        return @(Get-SoftwareDllVerificationPlan $Data -Injection:($Title -match 'process injection'))
    }
    $Kind='Unsupported'
    if ($Title -match '^Scheduled task ') { $Kind='Task' }
    elseif ($Title -match '^Unquoted service|^Service executable|^Service registry|^Potentially broad service-object') { $Kind='Service' }
    elseif ($Title -match '^Autorun executable') { $Kind='Autorun' }
    elseif ($Title -match '^Startup folder|^System PATH') { $Kind='Directory' }
    elseif ($Title -match '^AlwaysInstallElevated') { $Kind='Installer' }
    elseif ($Title -match '^Sensitive user right') { $Kind='Privilege' }
    elseif ($Title -match '^Safe DLL search') { $Kind='DllPolicy' }
    elseif ($Title -match '^Image File Execution Options') { $Kind='IFEO' }
    if ($Kind -eq 'Unsupported') { return @(Get-ConfigurationVerificationPlan $Title) }

    $Whoami=ConvertTo-PowerShellLiteral (Join-Path $env:SystemRoot 'System32\whoami.exe')
    $Steps.Add((New-VerificationStep 'Caller token' @'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
[pscustomobject]@{User=$identity.Name;UserSid=$identity.User.Value;IsAdministrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator);GroupSids=@($identity.Groups | ForEach-Object {$_.Value})}
'@ 'Records the verification caller. IsAdministrator=False may describe a filtered administrator; inspect whoami group attributes for deny-only memberships.'))
    $Steps.Add((New-VerificationStep 'Caller groups and privileges' ("& $Whoami /all`nif (`$LASTEXITCODE -ne 0) { throw 'whoami.exe failed.' }") 'Complete native whoami output establishes integrity level, group attributes and privilege state.'))

    $FilePath='';$DirectoryPath='';$RegistryPath=''
    switch ($Kind) {
        'Task' {
            if (-not $Data.TaskName -or -not $Data.TaskPath) { throw 'Saved task identity is incomplete.' }
            if ($Data.TaskPath -notmatch '^\\' -or $Data.TaskPath -match '[\r\n]' -or $Data.TaskName -match '[\\/\r\n]') { throw 'Invalid local task identity.' }
            $CmdletPath=([string]$Data.TaskPath).TrimEnd([char]92)+'\'
            $Prefix='$p='+(ConvertTo-PowerShellLiteral $CmdletPath)+"`n"+'$n='+(ConvertTo-PowerShellLiteral $Data.TaskName)+"`n"
            $Steps.Add((New-VerificationStep 'Registered task context' ($Prefix+@'
$task=Get-ScheduledTask -TaskPath $p -TaskName $n -ErrorAction Stop
[pscustomobject]@{
    TaskName=$task.TaskName;TaskPath=$task.TaskPath;State=[string]$task.State
    UserId=$task.Principal.UserId;GroupId=$task.Principal.GroupId
    LogonType=[string]$task.Principal.LogonType;RunLevel=[string]$task.Principal.RunLevel
    Enabled=$task.Settings.Enabled;AllowDemandStart=$task.Settings.AllowDemandStart
    Actions=@($task.Actions | Select-Object Execute,Arguments,WorkingDirectory,ClassId,Data)
    Triggers=@($task.Triggers | Select-Object @{Name='Type';Expression={$_.CimClass.CimClassName}},Enabled,StartBoundary,EndBoundary,UserId,Subscription,StateChange,Delay,RandomDelay)
}
'@) 'Queries the registered definition. Group principals and COM actions are retained. SYSTEM ignores RunLevel; HighestAvailable alone does not establish SYSTEM execution. Disabled tasks need an additional enable/launch path.'))
            $Steps.Add((New-VerificationStep 'Registered task security descriptor' ($Prefix+@'
$service=New-Object -ComObject 'Schedule.Service'
$service.Connect()
$folderPath=$p.TrimEnd([char]92)
if (-not $folderPath) {$folderPath='\'}
$registered=$service.GetFolder($folderPath).GetTask($n)
$sddl=$registered.GetSecurityDescriptor(7)
$sd=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
[pscustomobject]@{Sddl=$sddl;Owner=[string]$sd.Owner;Group=[string]$sd.Group;Aces=@($sd.DiscretionaryAcl | Select-Object AceType,AceFlags,@{Name='Sid';Expression={[string]$_.SecurityIdentifier}},AccessMask)}
'@) 'Reads owner, group and the full scheduler DACL using a COM folder path without a trailing slash. Broad Allow ACEs must be evaluated with deny ACEs and the caller token; this is not a task-modification test.'))
            if ($Title -match '^Scheduled task definition') {$FilePath=[string]$Data.TaskFile}
            elseif ($Title -match 'directory') {if ($Data.Action) {$DirectoryPath=Split-Path -Parent ([string]$Data.Action)}}
            else {$FilePath=[string]$Data.Action}
        }
        'Service' {
            if (-not $Data.Name) {throw 'Saved service name is missing.'}
            if ($Data.Name -match '[\\/\r\n]') {throw 'Invalid local service name.'}
            $NameLiteral=ConvertTo-PowerShellLiteral $Data.Name
            $Sc=ConvertTo-PowerShellLiteral (Join-Path $env:SystemRoot 'System32\sc.exe')
            $Steps.Add((New-VerificationStep 'Service execution context' ("Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object Name -eq $NameLiteral | Select-Object Name,DisplayName,PathName,StartName,StartMode,State") 'Service identity and a subsequent launch determine the potential privilege gain; a path/ACL observation does not confirm execution.'))
            $Steps.Add((New-VerificationStep 'Service configuration' ("& $Sc qc $NameLiteral`nif (`$LASTEXITCODE -ne 0) {throw 'sc.exe qc failed.'}") 'Full service configuration query output. Query success does not imply change-configuration rights.'))
            $Steps.Add((New-VerificationStep 'Service security descriptor' ("& $Sc sdshow $NameLiteral`nif (`$LASTEXITCODE -ne 0) {throw 'sc.exe sdshow failed.'}") 'Review modification rights and deny rules in the service DACL; this query does not attempt a restart or configuration change.'))
            if ($Title -match '^Service executable is writable') {$FilePath=[string]$Data.Executable}
            elseif ($Title -match '^Service executable directory') {$DirectoryPath=[string]$Data.Directory}
            elseif ($Title -match '^Service registry') {$RegistryPath='HKLM:\SYSTEM\CurrentControlSet\Services\'+$Data.Name}
            elseif ($Title -match '^Unquoted service' -and $Data.Executable) {
                Assert-LocalVerificationPath ([string]$Data.Executable) 'File'
                $Steps.Add((New-VerificationStep 'Unquoted executable candidates' ('$exe='+(ConvertTo-PowerShellLiteral $Data.Executable)+"`n"+@'
foreach ($space in [regex]::Matches($exe,' ')) {
    $candidate=$exe.Substring(0,$space.Index)+'.exe'
    $parent=Split-Path -Parent $candidate
    [pscustomobject]@{Candidate=$candidate;Exists=(Test-Path -LiteralPath $candidate);Parent=$parent}
    if (Test-Path -LiteralPath $parent) {
        $acl=Get-Acl -LiteralPath $parent -ErrorAction Stop
        [pscustomobject]@{Path=$parent;Sddl=$acl.Sddl;Rules=@($acl.Access | Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags)}
    }
}
'@) 'Lists earlier executable candidates and their parent ACLs without creating files. Spaces alone are insufficient; a usable candidate, effective rights and privileged launch are required.'))
            }
        }
        'Autorun' {
            $RegistryPath=[string]$Data.RegistryPath
            if ($RegistryPath -and $RegistryPath -notmatch '^HK(LM|CU):\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Run(Once)?$') {throw 'Autorun registry path is outside the supported Run/RunOnce keys.'}
            if ($Title -match 'directory') {if ($Data.Executable) {$DirectoryPath=Split-Path -Parent ([string]$Data.Executable)}}
            else {$FilePath=[string]$Data.Executable}
        }
        'Directory' {
            $DirectoryPath=[string]$Data.Path
            if ($Title -match '^System PATH') {
                $Steps.Add((New-VerificationStep 'Machine executable search path' "[Environment]::GetEnvironmentVariable('Path','Machine') -split ';'" 'Identify a higher-privilege consumer and its actual search order. A writable PATH directory alone does not establish DLL/executable loading.'))
            }
        }
        'Installer' {
            foreach ($Hive in @('HKLM','HKCU')) {
                $Steps.Add((New-VerificationStep "$Hive installer policy" ("Get-ItemProperty -LiteralPath '${Hive}:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -ErrorAction Stop | Select-Object AlwaysInstallElevated") 'Both machine and tested-user values must be 1. Missing values are unavailable, not evidence of an enabled policy. Installation/application controls still apply.'))
            }
        }
        'Privilege' {
            $Steps.Add((New-VerificationStep 'Current token privileges' ("& $Whoami /priv`nif (`$LASTEXITCODE -ne 0) {throw 'whoami.exe /priv failed.'}") 'Compare the assigned right to the current token. Disabled is not necessarily absent; possession alone does not prove a usable abuse path.'))
        }
        'DllPolicy' {
            $Steps.Add((New-VerificationStep 'DLL search policy' "Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name SafeDllSearchMode,CWDIllegalInDllSearch -ErrorAction Continue | Select-Object SafeDllSearchMode,CWDIllegalInDllSearch" 'Requires a privileged process that actually searches a writable location for a specific DLL; registry policy alone does not prove escalation.'))
        }
        'IFEO' {
            foreach ($Root in @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
                $Steps.Add((New-VerificationStep 'Debugger registry entries' ('$root='+(ConvertTo-PowerShellLiteral $Root)+"`n"+@'
Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
    $key=$_
    $debugger=$key.GetValue('Debugger')
    if ($debugger) {
        $acl=Get-Acl -LiteralPath $key.PSPath -ErrorAction Stop
        [pscustomobject]@{Key=$key.Name;Debugger=$debugger;Sddl=$acl.Sddl;Rules=@($acl.Access | Select-Object IdentityReference,RegistryRights,AccessControlType,IsInherited)}
    }
}
'@) 'Debugger redirects can be legitimate. Review the affected executable identity and debugger/registry effective access.'))
            }
        }
    }
    if ($RegistryPath) {
        Assert-LocalVerificationPath $RegistryPath 'Registry'
        $Q=ConvertTo-PowerShellLiteral $RegistryPath
        $Steps.Add((New-VerificationStep 'Registry values and permissions' ("`$path=$Q`n"+@'
if ($path -like 'HKLM:\SYSTEM\CurrentControlSet\Services\*') {
    $key=Get-Item -LiteralPath $path -ErrorAction Stop
    [pscustomobject]@{ImagePath=$key.GetValue('ImagePath');ObjectName=$key.GetValue('ObjectName');Start=$key.GetValue('Start');Type=$key.GetValue('Type');ErrorControl=$key.GetValue('ErrorControl')}
} else {Get-ItemProperty -LiteralPath $path -ErrorAction Stop}
$acl=Get-Acl -LiteralPath $path -ErrorAction Stop
[pscustomobject]@{Path=$path;Sddl=$acl.Sddl;Rules=@($acl.Access | Select-Object IdentityReference,RegistryRights,AccessControlType,IsInherited,InheritanceFlags,PropagationFlags)}
'@) 'Full selected registry values and DACL entries. Allow entries alone do not establish effective modification rights or privileged consumption.'))
    }
    $AclPath=if ($FilePath) {$FilePath} else {$DirectoryPath}
    if ($Kind -in @('Task','Autorun','Directory') -and -not $AclPath) {throw 'Saved filesystem target is missing; the finding cannot be fully verified.'}
    if ($Kind -eq 'Service' -and $Title -match '^Service executable' -and -not $AclPath) {throw 'Saved service filesystem target is missing.'}
    if ($Kind -eq 'Service' -and $Title -match '^Unquoted service' -and -not $Data.Executable) {throw 'Saved unquoted executable target is missing.'}
    if ($AclPath) {
        Assert-LocalVerificationPath $AclPath 'File'
        $Q=ConvertTo-PowerShellLiteral $AclPath
        $Steps.Add((New-VerificationStep 'Filesystem security descriptor' ("`$path=$Q`n"+@'
$acl=Get-Acl -LiteralPath $path -ErrorAction Stop
[pscustomobject]@{Path=$path;Owner=$acl.Owner;Sddl=$acl.Sddl;Rules=@($acl.Access | ForEach-Object {
    $ace=$_;$sid=$null
    try {$sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value} catch {}
    $rights=[string]$ace.FileSystemRights
    [pscustomobject]@{Identity=$ace.IdentityReference.Value;Sid=$sid;BroadWriteAllow=($ace.AccessControlType -eq 'Allow' -and $sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545') -and $rights -match 'FullControl|Modify|Write|CreateFiles|CreateDirectories|AppendData|ChangePermissions|TakeOwnership');Rights=$rights;AccessControlType=[string]$ace.AccessControlType;IsInherited=$ace.IsInherited;InheritanceFlags=[string]$ace.InheritanceFlags;PropagationFlags=[string]$ace.PropagationFlags}
})}
'@) 'All selected permission entries, including deny and inheritance/propagation flags, are retained. Effective access and the consuming execution identity still require interpretation.'))
    }
    if ($FilePath) {
        $Q=ConvertTo-PowerShellLiteral $FilePath
        $Steps.Add((New-VerificationStep 'Existing-file write-open probe' ("`$path=$Q`n"+@'
$handle=$null
try {
    $handle=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite)
    [pscustomobject]@{Path=$path;WriteOpenSucceeded=$true;BytesWritten=0;FailureKind=$null;Error=$null}
} catch {
    $exception=$_.Exception
    while ($exception.InnerException) {$exception=$exception.InnerException}
    $kind=switch ($exception.HResult -band 0xffff) {5 {'AccessDenied'} 32 {'SharingViolation'} 33 {'LockViolation'} 2 {'NotFound'} 3 {'NotFound'} default {'Other'}}
    [pscustomobject]@{Path=$path;WriteOpenSucceeded=$false;BytesWritten=0;FailureKind=$kind;HResult=$exception.HResult;Error=$exception.Message}
} finally {if ($null -ne $handle) {$handle.Dispose()}}
'@) 'Opens an existing file for write access and immediately closes it without writing bytes. It establishes access for this caller only; no modified action is executed.'))
    }
    return @($Steps.ToArray())
}

function Get-ConfigurationVerificationPlan {
    param([string]$Title)
    # Commands below are maintained source code, never command text supplied by JSON.
    $Command='';$Explanation='Review the selected configuration against the source finding. Missing values, defaults, OS support and collection errors require interpretation.'
    $Registry=@()
    switch -Regex ($Title) {
        '^User Account Control|^Remote UAC' { $Registry=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop,LocalAccountTokenFilterPolicy'); break }
        '^WDigest' {$Registry=@('HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential'); break}
        '^LSA protection|^NTLM compatibility|^Anonymous users' {$Registry=@('HKLM:\SYSTEM\CurrentControlSet\Control\Lsa','RunAsPPL,LmCompatibilityLevel,EveryoneIncludesAnonymous'); break}
        '^LLMNR' {$Registry=@('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient','EnableMulticast'); break}
        '^PowerShell Script Block' {$Registry=@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging','EnableScriptBlockLogging'); break}
        '^PowerShell Module' {$Registry=@('HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging','EnableModuleLogging'); break}
        '^Non-administrators may install' {$Registry=@('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint','RestrictDriverInstallationToAdministrators,NoWarningNoElevationOnInstall,UpdatePromptSettings'); break}
        '^Command-line inclusion' {$Registry=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit','ProcessCreationIncludeCmdLine_Enabled'); break}
        '^LDAP server signing|^LDAP channel' {$Registry=@('HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters','LDAPServerIntegrity,LdapEnforceChannelBinding'); break}
        '^Automatic administrative logon' {
            $Command=@'
$path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$key=Get-Item -LiteralPath $path -ErrorAction Stop
[pscustomobject]@{AutoAdminLogon=$key.GetValue('AutoAdminLogon');DefaultUserName=$key.GetValue('DefaultUserName');DefaultDomainName=$key.GetValue('DefaultDomainName');DefaultPasswordConfigured=($key.GetValueNames() -contains 'DefaultPassword')}
'@
            $Explanation='Checks configured logon and password-value presence. No stored password value is read.'; break
        }
        '^Microsoft Defender real-time' {$Command='Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected'; break}
        '^Defender script|^Potentially unwanted|^Microsoft Defender exclusions' {$Command='Get-MpPreference -ErrorAction Stop | Select-Object DisableScriptScanning,PUAProtection,ExclusionPath,ExclusionProcess,ExclusionExtension,ExclusionIpAddress'; $Explanation='Complete selected preferences. Placeholder exclusions can be inert; listed exclusions alone do not prove effective protection bypass.'; break}
        '^Windows Firewall profile|^Dropped firewall' {$Command='Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogBlocked,LogAllowed,LogFileName,LogMaxSizeKilobytes'; break}
        '^Broad inbound firewall' {
            $Command=@'
Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction Stop | ForEach-Object {
    $rule=$_
    [pscustomobject]@{Name=$rule.Name;DisplayName=$rule.DisplayName;Profile=[string]$rule.Profile;AddressFilters=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object LocalAddress,RemoteAddress);PortFilters=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object Protocol,LocalPort,RemotePort);Applications=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop | Select-Object Program)}
}
'@
            $Explanation='Includes all selected enabled inbound allow rules and associated filters. Broad addresses or ports need application, profile and effective-policy context.'; break
        }
        '^SMBv1|^SMB server signing' {$Command='Get-SmbServerConfiguration -ErrorAction Stop | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature'; break}
        '^SMB client signing|^Insecure SMB guest' {$Command='Get-SmbClientConfiguration -ErrorAction Stop | Select-Object RequireSecuritySignature,EnableSecuritySignature,EnableInsecureGuestLogons'; break}
        '^Broad write access to SMB' {$Command='Get-SmbShare -ErrorAction Stop | ForEach-Object { $share=$_; Get-SmbShareAccess -Name $share.Name -ErrorAction Stop | Select-Object @{Name="Share";Expression={$share.Name}},AccountName,AccessControlType,AccessRight }'; $Explanation='Share permissions must be combined with filesystem permissions and the caller token; a broad share Allow is insufficient by itself.'; break}
        '^RDP is enabled|^Remote Desktop' {
            $Command="Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop | Select-Object fDenyTSConnections`nGet-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication,SecurityLayer,PortNumber -ErrorAction Stop | Select-Object UserAuthentication,SecurityLayer,PortNumber"; break
        }
        '^WinRM TrustedHosts' {$Command='Get-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop | Select-Object Name,Value'; break}
        '^No enforced AppLocker' {$Command='Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop'; $Explanation='Preserves the complete effective policy XML. Rule presence and enforcement need edition, service and collection context.'; break}
        '^NetBIOS' {$Command='Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop | Where-Object IPEnabled | Select-Object Description,Index,TcpipNetbiosOptions'; break}
        'server protocol is explicitly' {
            $Command=@'
foreach ($protocol in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')) {
    $path='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'+$protocol+'\Server'
    Get-ItemProperty -LiteralPath $path -Name Enabled,DisabledByDefault -ErrorAction Continue | Select-Object @{Name='Protocol';Expression={$protocol}},Enabled,DisabledByDefault
}
'@; break
        }
        '^Security event log' {$Command='Get-WinEvent -ListLog Security -ErrorAction Stop | Select-Object LogName,IsEnabled,MaximumSizeInBytes,LogMode,RecordCount,LogFilePath'; break}
        '^Sysmon service' {$Command="Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object Name -in @('Sysmon','Sysmon64') | Select-Object Name,State,StartMode,PathName"; break}
        '^No installed Windows update' {$Command='Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn'; $Explanation='Retains the complete selected hotfix inventory. Get-HotFix is not a complete update inventory and does not prove every applicable update is installed.'; break}
        '^System has a pending reboot' {
            $Command=@'
[pscustomobject]@{
    ComponentServicing=Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    WindowsUpdate=Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
}
Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Continue | Select-Object PendingFileRenameOperations
'@; break
        }
        '^Configured WSUS' {$Command="Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer,WUStatusServer -ErrorAction Stop | Select-Object WUServer,WUStatusServer`nGet-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name UseWUServer -ErrorAction Stop | Select-Object UseWUServer"; break}
        '^UEFI Secure Boot' {$Command='[pscustomobject]@{Enabled=(Confirm-SecureBootUEFI -ErrorAction Stop)}'; break}
        '^BitLocker' {$Command='Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeType,VolumeStatus,ProtectionStatus,EncryptionPercentage,EncryptionMethod'; break}
        '^Legacy PowerShell' {$Command="Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object FeatureName -like '*PowerShell*' | Select-Object FeatureName,State"; break}
        '^Permanent WMI' {$Command='Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | Select-Object Filter,Consumer'; $Explanation='Registration can be legitimate. Validate management-software ownership; consumers are not executed.'; break}
        '^Built-in Guest' {$Command="Get-LocalUser -ErrorAction Stop | Where-Object { `$_.SID.Value -match '-501$' } | Select-Object Name,SID,Enabled,LastLogon"; break}
        '^Minimum password|^Account lockout|^Reversible password' {
            $Secedit=ConvertTo-PowerShellLiteral (Join-Path $env:SystemRoot 'System32\secedit.exe')
            $Command='$secedit='+$Secedit+"`n"+@'
$tempFile=Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName()+'.inf')
$logFile=$tempFile+'.log'
try {
    & $secedit /export /cfg $tempFile /areas SECURITYPOLICY /log $logFile /quiet
    if ($LASTEXITCODE -ne 0) {throw ('secedit export failed: '+$LASTEXITCODE)}
    Get-Content -LiteralPath $tempFile -ErrorAction Stop | Where-Object {$_ -match '^\s*(MinimumPasswordLength|PasswordComplexity|ClearTextPassword|LockoutBadCount|ResetLockoutCount|LockoutDuration|MinimumPasswordAge|MaximumPasswordAge)\s*='}
} finally {
    Remove-Item -LiteralPath $tempFile,$logFile -Force -ErrorAction SilentlyContinue
}
'@
            $Explanation='Exports selected local security-policy fields to temporary files and cleans them up. Domain and fine-grained policies can supersede local account policy.'; break
        }
        '^Unattended installation' {
            $Command=@'
foreach ($path in @("$env:SystemRoot\Panther\Unattend.xml","$env:SystemRoot\Panther\Unattend\Unattend.xml","$env:SystemRoot\System32\Sysprep\unattend.xml", "$env:SystemDrive\unattend.xml")) {
    if (Test-Path -LiteralPath $path) {Get-Item -LiteralPath $path -ErrorAction Stop | Select-Object FullName,Length,CreationTime,LastWriteTime}
}
'@
            $Explanation='Checks known setup-file metadata only. Contents and potential credentials are not collected.'; break
        }
    }
    if ($Registry.Count) {
        $Names=@($Registry[1].Split(',') | ForEach-Object {ConvertTo-PowerShellLiteral $_}) -join ','
        $Command='Get-ItemProperty -LiteralPath '+(ConvertTo-PowerShellLiteral $Registry[0])+' -Name '+$Names+' -ErrorAction Continue | Select-Object '+$Registry[1]
    }
    if ($Command) { New-VerificationStep 'Current local configuration' $Command $Explanation }
}

function Assert-LocalVerificationPath {
    param([string]$Path,[ValidateSet('File','Registry')][string]$Kind)
    if ($Kind -eq 'Registry') {
        if ($Path -notmatch '^HK(LM|CU):\\') {throw 'Verification only supports local HKLM/HKCU registry paths.'}
    } elseif ($Path -notmatch '^[A-Za-z]:\\' -or $Path -match '[\r\n]') {
        throw 'Verification only supports absolute local drive paths; UNC/device/relative paths are not accepted.'
    } else {
        $Drive=[IO.DriveInfo]::new($Path.Substring(0,3))
        if ($Drive.DriveType -eq [IO.DriveType]::Network) {throw 'Mapped network drives are not local verification targets.'}
    }
}

function Invoke-VerificationStep {
    param($Step,[ValidateRange(1,300)][int]$TimeoutSeconds=30)
    $Started=Get-Date
    $Timer=[Diagnostics.Stopwatch]::StartNew()
    $Ps=[powershell]::Create()
    $InputBuffer=New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $InputBuffer.Complete()
    $OutputBuffer=New-Object 'System.Management.Automation.PSDataCollection[psobject]'
    $Status='Completed';$Failure='';$Async=$null
    $OutputData=@();$Output='';$Errors=@();$Warnings=@();$Information=@();$Verbose=@();$Debug=@()
    try {
        $null=$Ps.AddScript($Step.Command)
        $Async=$Ps.BeginInvoke($InputBuffer,$OutputBuffer)
        if (-not $Async.AsyncWaitHandle.WaitOne($TimeoutSeconds*1000)) {
            $Status='TimedOut';$Ps.Stop()
        }
        try {$null=$Ps.EndInvoke($Async)} catch {if ($Status -ne 'TimedOut') {$Status='Error';$Failure=$_.Exception.Message}}
        $OutputData=@($OutputBuffer | ForEach-Object {$_})
        $Output=Convert-ToSafeString $OutputData
        $Errors=@($Ps.Streams.Error | ForEach-Object {[pscustomobject]@{Message=$_.ToString();FullyQualifiedErrorId=$_.FullyQualifiedErrorId;Category=[string]$_.CategoryInfo;Position=$_.InvocationInfo.PositionMessage;Details=$_.ErrorDetails.Message}})
        if ($Errors.Count -gt 0 -and $Status -eq 'Completed') {$Status='Error'}
        $Warnings=@($Ps.Streams.Warning | ForEach-Object {$_.Message})
        $Information=@($Ps.Streams.Information | ForEach-Object {$_.MessageData})
        $Verbose=@($Ps.Streams.Verbose | ForEach-Object {$_.Message})
        $Debug=@($Ps.Streams.Debug | ForEach-Object {$_.Message})
    } catch {
        $Status='Error';$Failure=$_.Exception.Message
        $OutputData=@($OutputBuffer | ForEach-Object {$_})
        try {$Output=Convert-ToSafeString $OutputData} catch {throw 'Verification output could not be serialized completely; report generation stopped to avoid losing evidence.'}
        $Errors=@([pscustomobject]@{Message=$Failure;FullyQualifiedErrorId=$_.FullyQualifiedErrorId;Category=[string]$_.CategoryInfo;Position=$_.InvocationInfo.PositionMessage})
    } finally {
        $Timer.Stop()
        if ($Async) {$Async.AsyncWaitHandle.Dispose()}
        $Ps.Dispose();$InputBuffer.Dispose();$OutputBuffer.Dispose()
    }
    $Explanation=$Step.Explanation
    if ($Status -eq 'TimedOut') {$Explanation+=' The check timed out; any collected output is partial and cannot be treated as a pass.'}
    elseif ($Status -eq 'Error') {$Explanation+=' The query had errors; review the complete errors and any partial output. This does not prove the issue is absent.'}
    elseif (@($OutputData | Where-Object {$null -ne $_}).Count -eq 0) {$Explanation+=' The query returned no data. This is not automatically a pass.'}
    if ($Step.Name -eq 'Existing-file write-open probe' -and $OutputData.Count) {
        if ($OutputData[0].WriteOpenSucceeded) {$Explanation+=' Write-open succeeded for the recorded caller; execution-based escalation remains untested.'}
        else {$Explanation+=' Write-open was not confirmed. Failure kind: '+$OutputData[0].FailureKind+'. A sharing/lock conflict is not an access denial.'}
    }
    [pscustomobject]@{Name=$Step.Name;Command=$Step.Command;Status=$Status;StartedAt=$Started.ToString('o');CompletedAt=(Get-Date).ToString('o');DurationMilliseconds=$Timer.ElapsedMilliseconds;Output=$Output;OutputData=$OutputData;Errors=$Errors;Warnings=$Warnings;Information=$Information;Verbose=$Verbose;Debug=$Debug;Failure=$Failure;Explanation=$Explanation}
}

function Invoke-FindingVerification {
    param($Finding,[ValidateRange(1,300)][int]$TimeoutSeconds=30)
    $Started=(Get-Date).ToString('o')
    try {$Plan=@(Get-LocalVerificationPlan $Finding)} catch {
        return [pscustomobject]@{Status='Unavailable';StartedAt=$Started;CompletedAt=(Get-Date).ToString('o');Explanation=('Could not build a local verification plan: '+$_.Exception.Message);Steps=@()}
    }
    if ($Plan.Count -eq 0) {
        $Explanation='No supported automatic verification plan for this finding. Historical evidence is preserved; report-provided commands were not executed.'
        if ($Finding.Finding -match '^Windows Update Agent') {$Explanation='A fresh Windows Update Agent search can contact an update service and is excluded from this local verification helper. Rerun the main assessment without -SkipWindowsUpdateScan to refresh this finding.'}
        return [pscustomobject]@{Status='NotApplicable';StartedAt=$Started;CompletedAt=(Get-Date).ToString('o');Explanation=$Explanation;Steps=@()}
    }
    $Results=@(foreach ($Step in $Plan) {Invoke-VerificationStep $Step $TimeoutSeconds})
    $Failed=@($Results | Where-Object Status -ne 'Completed')
    $Status=if ($Failed.Count -eq 0) {'ChecksCompleted'} elseif ($Failed.Count -eq $Results.Count) {'Unavailable'} else {'Partial'}
    $Explanation='These are fresh local checks, separate from the source scan. Completed means the checks finished, not that the finding is confirmed or disproved. No task/service action was modified or executed.'
    $Token=$Results | Where-Object Name -eq 'Caller token' | Select-Object -First 1
    if ($Token.OutputData.Count -gt 0 -and $Token.OutputData[0].IsAdministrator) {
        $Explanation+=' Verification ran elevated; successful file-write probes do not establish access for a standard user. Repeat non-elevated for that assessment.'
    }
    [pscustomobject]@{Status=$Status;StartedAt=$Started;CompletedAt=(Get-Date).ToString('o');Explanation=$Explanation;Steps=$Results}
}

function Assert-LocalSoftwarePath {
    param([string]$Path)
    Assert-LocalVerificationPath $Path 'File'
    $full=[IO.Path]::GetFullPath($Path)
    $cursor=$full
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse points are excluded from DLL review.'}
        }
        $cursor=Split-Path -Parent $cursor
    }
    return $full
}

function Read-PeInteger {
    param([IO.BinaryReader]$Reader,[long]$Offset,[int]$Width)
    if ($Offset -lt 0 -or $Offset+$Width -gt $Reader.BaseStream.Length) {throw 'PE field is outside the file.'}
    $Reader.BaseStream.Position=$Offset
    switch ($Width) {2 {return $Reader.ReadUInt16()} 4 {return $Reader.ReadUInt32()} 8 {return $Reader.ReadUInt64()} default {throw 'Unsupported PE integer width.'}}
}

function Convert-PeRvaToOffset {
    param([uint64]$Rva,$Sections,[uint64]$HeaderSize,[long]$FileLength)
    if ($Rva -lt $HeaderSize -and $Rva -lt $FileLength) {return [long]$Rva}
    foreach ($section in $Sections) {
        if ($Rva -ge $section.VirtualAddress -and $Rva -lt ([uint64]$section.VirtualAddress+[Math]::Max($section.VirtualSize,$section.RawSize))) {
            $delta=$Rva-$section.VirtualAddress
            if ($delta -ge $section.RawSize -or $section.RawOffset+$delta -ge $FileLength) {throw 'PE RVA points into unbacked or truncated section data.'}
            return [long]($section.RawOffset+$delta)
        }
    }
    throw 'PE RVA does not map to file data.'
}

function Get-PeDllImports {
    param([string]$Path)
    $reader=$null;$stream=$null;$imports=New-Object 'System.Collections.Generic.List[object]'
    $architecture='Unknown';$clr=$false
    try {
        $Path=Assert-LocalSoftwarePath $Path
        $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        $reader=[IO.BinaryReader]::new($stream)
        if ((Read-PeInteger $reader 0 2) -ne 0x5a4d) {throw 'Not a DOS/PE image.'}
        $pe=[long](Read-PeInteger $reader 0x3c 4)
        if ((Read-PeInteger $reader $pe 4) -ne 0x4550) {throw 'Invalid PE signature.'}
        $machine=Read-PeInteger $reader ($pe+4) 2
        $architecture=switch ($machine) {0x14c {'x86'} 0x8664 {'x64'} 0xaa64 {'ARM64'} default {'Machine 0x{0:X4}' -f $machine}}
        $sectionCount=Read-PeInteger $reader ($pe+6) 2
        if ($sectionCount -gt 96) {throw 'PE section count exceeds supported bounds.'}
        $optionalSize=Read-PeInteger $reader ($pe+20) 2
        $optional=$pe+24
        $magic=Read-PeInteger $reader $optional 2
        if ($magic -eq 0x10b) {$directoryOffset=96;$countOffset=92;$imageBase=Read-PeInteger $reader ($optional+28) 4}
        elseif ($magic -eq 0x20b) {$directoryOffset=112;$countOffset=108;$imageBase=Read-PeInteger $reader ($optional+24) 8}
        else {throw 'Unsupported optional-header magic.'}
        if ($optionalSize -lt $directoryOffset -or $optional+$optionalSize -gt $stream.Length) {throw 'Truncated optional header.'}
        $directoryCount=Read-PeInteger $reader ($optional+$countOffset) 4
        if ($directoryCount -gt 16 -or $directoryOffset+8*$directoryCount -gt $optionalSize) {throw 'Invalid data-directory count.'}
        $headerSize=Read-PeInteger $reader ($optional+60) 4
        $sections=@(for ($i=0;$i -lt $sectionCount;$i++) {
            $offset=$optional+$optionalSize+40*$i
            if ($offset+40 -gt $stream.Length) {throw 'Truncated section header.'}
            [pscustomobject]@{VirtualSize=[uint64](Read-PeInteger $reader ($offset+8) 4);VirtualAddress=[uint64](Read-PeInteger $reader ($offset+12) 4);RawSize=[uint64](Read-PeInteger $reader ($offset+16) 4);RawOffset=[uint64](Read-PeInteger $reader ($offset+20) 4)}
        })
        if ($directoryCount -gt 14) {$clr=(Read-PeInteger $reader ($optional+$directoryOffset+14*8) 4) -ne 0}
        foreach ($table in @([pscustomobject]@{Index=1;Width=20;Kind='Import'},[pscustomobject]@{Index=13;Width=32;Kind='DelayImport'})) {
            if ($directoryCount -le $table.Index) {continue}
            $entry=$optional+$directoryOffset+8*$table.Index
            $rva=Read-PeInteger $reader $entry 4;$size=Read-PeInteger $reader ($entry+4) 4
            if ($rva -eq 0 -and $size -eq 0) {continue}
            if ($rva -eq 0 -or $size -lt $table.Width) {throw 'Invalid import-table directory.'}
            $count=[Math]::Floor($size/$table.Width)
            if ($count -gt 4096) {throw 'Import table exceeds supported descriptor bounds.'}
            $terminated=$false
            for ($i=0;$i -lt $count;$i++) {
                $offset=Convert-PeRvaToOffset ([uint64]$rva+$i*$table.Width) $sections $headerSize $stream.Length
                $fields=@(for ($f=0;$f -lt $table.Width/4;$f++) {Read-PeInteger $reader ($offset+4*$f) 4})
                if (@($fields | Where-Object {$_ -ne 0}).Count -eq 0) {$terminated=$true;break}
                $nameRva=if ($table.Kind -eq 'Import') {[uint64]$fields[3]} else {[uint64]$fields[1]}
                if ($table.Kind -eq 'DelayImport' -and ($fields[0] -band 1) -eq 0) {
                    if ($nameRva -lt $imageBase) {throw 'Invalid VA-based delay-import name.'}
                    $nameRva-=$imageBase
                }
                if (-not $nameRva) {throw 'Import descriptor has no name.'}
                $nameOffset=Convert-PeRvaToOffset $nameRva $sections $headerSize $stream.Length
                $stream.Position=$nameOffset;$chars=New-Object 'System.Collections.Generic.List[byte]';$ended=$false
                for ($c=0;$c -lt 512;$c++) {
                    if ($stream.Position -ge $stream.Length) {break}
                    $b=$reader.ReadByte();if ($b -eq 0) {$ended=$true;break};$chars.Add($b)
                }
                if (-not $ended -or -not $chars.Count) {throw 'Import name is empty, truncated or too long.'}
                $name=[Text.Encoding]::ASCII.GetString($chars.ToArray())
                $imports.Add([pscustomobject]@{DllName=$name;ImportKind=$table.Kind})
            }
            if (-not $terminated) {throw 'Import table lacks a bounded terminator.'}
        }
        $status='Collected';$errorMessage=$null
    } catch {$status='Unavailable';$errorMessage=$_.Exception.Message}
    finally {if ($reader) {$reader.Dispose()} elseif ($stream) {$stream.Dispose()}}
    [pscustomobject]@{Path=$Path;Status=$status;Architecture=$architecture;HasClrHeader=$clr;Imports=@($imports.ToArray() | Sort-Object DllName,ImportKind -Unique);Error=$errorMessage;Coverage='Static and delay imports only. Dynamic LoadLibrary, .NET/plugin resolution, embedded manifests and runtime search flags are not resolved.'}
}

function Get-SoftwareDllAcl {
    param([string]$Path)
    $rules=@();$isDirectory=$false
    try {
        $Path=Assert-LocalSoftwarePath $Path
        $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop;$isDirectory=$item.PSIsContainer
        $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules=@(foreach ($ace in $acl.Access) {
            $sid=$null;try {$sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value} catch {}
            $mask=[long]$ace.FileSystemRights
            $applies=($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
            $broad=$ace.AccessControlType -eq 'Allow' -and $applies -and $sid -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')
            $riskMask=if ($isDirectory) {0xC0042} else {0xD0006}
            [pscustomobject]@{Identity=$ace.IdentityReference.Value;Sid=$sid;BroadWriteAllow=($broad -and ($mask -band $riskMask) -ne 0);Rights=[string]$ace.FileSystemRights;AccessMask=$mask;AccessControlType=[string]$ace.AccessControlType;IsInherited=$ace.IsInherited;InheritanceFlags=[string]$ace.InheritanceFlags;PropagationFlags=[string]$ace.PropagationFlags;AppliesToObject=$applies}
        })
        [pscustomobject]@{Path=$Path;Status='Collected';IsDirectory=$isDirectory;Owner=$acl.Owner;Sddl=$acl.Sddl;Rules=$rules;BroadWriteAllow=(@($rules | Where-Object BroadWriteAllow).Count -gt 0);Error=$null}
    } catch {[pscustomobject]@{Path=$Path;Status='Unavailable';IsDirectory=$isDirectory;Rules=$rules;BroadWriteAllow=$false;Error=$_.Exception.Message}}
}

function Get-KnownSoftwareDllNames {
    $names=New-Object 'System.Collections.Generic.List[string]'
    foreach ($path in @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs','HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs32')) {
        if (-not (Test-Path -LiteralPath $path)) {continue}
        try {
            $key=Get-Item -LiteralPath $path -ErrorAction Stop
            foreach ($name in $key.GetValueNames()) { $value=[string]$key.GetValue($name);if ($value -match '^[^\\/:]+\.dll$') {$names.Add($value.ToLowerInvariant())} }
        } catch {Add-CollectionError 'KnownDLLs inventory' $_.Exception.Message}
    }
    return @($names.ToArray() | Sort-Object -Unique)
}

function Get-InstalledSoftwareInventory {
    # Uninstall registry keys do not trigger MSI repair (unlike Win32_Product).
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path -LiteralPath $root)) {continue}
        try {
            foreach ($key in Get-ChildItem -LiteralPath $root -ErrorAction Stop) {
                try {
                    if (-not $key.GetValue('DisplayName')) {continue}
                    [pscustomobject]@{DisplayName=$key.GetValue('DisplayName');DisplayVersion=$key.GetValue('DisplayVersion');Publisher=$key.GetValue('Publisher');InstallDate=$key.GetValue('InstallDate');InstallLocation=$key.GetValue('InstallLocation');DisplayIcon=$key.GetValue('DisplayIcon');RegistryKey=$key.Name;InventorySource=$root;PackageType='UninstallRegistry'}
                } catch {Add-CollectionError ('Software registry '+$key.Name) $_.Exception.Message}
            }
        } catch {Add-CollectionError ('Software inventory '+$root) $_.Exception.Message}
    }
    if (Get-Command Get-AppxPackage -ErrorAction SilentlyContinue) {
        try {
            $packages=if (Test-IsAdministrator) {Get-AppxPackage -AllUsers -ErrorAction Stop} else {Get-AppxPackage -ErrorAction Stop}
            foreach ($package in $packages) {
                [pscustomobject]@{DisplayName=$package.Name;DisplayVersion=[string]$package.Version;Publisher=$package.Publisher;InstallDate=$null;InstallLocation=$package.InstallLocation;DisplayIcon=$null;RegistryKey=$null;InventorySource='AppxPackage';PackageType='MSIX/AppX';PackageFullName=$package.PackageFullName}
            }
        } catch {Add-CollectionError 'AppX/MSIX software inventory' $_.Exception.Message}
    } else {Add-CollectionError 'AppX/MSIX software inventory' 'Get-AppxPackage is unavailable; package coverage is not complete.'}
}

function Initialize-SoftwareDllNativeProbe {
    if ('HostSecurity.DllAccessV31' -as [type]) {return}
    # Only OpenProcess/OpenProcessToken, token/image queries and CloseHandle.
    # No process-memory, thread creation, DLL-loading or privilege-adjustment APIs.
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
namespace HostSecurity {
 public class DllAccessResult {
  public int ProcessId; public string RequestedAccess="0x0000043A";
  public bool InjectionRightsGranted; public int OpenProcessError;
  public string ImagePath, TargetUserSid, CallerUserSid, Error;
  public int TargetIntegrityRid=-1, CallerIntegrityRid=-1;
  public bool HigherIntegrity, DifferentUser, CallerIsAdministrator;
 }
 public static class DllAccessV31 {
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,int pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr handle,uint flags,StringBuilder name,ref uint size);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint rights,out IntPtr token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int cls,IntPtr buffer,int len,out int size);
  static string TokenSid(IntPtr token,int cls) {
   int size; GetTokenInformation(token,cls,IntPtr.Zero,0,out size);
   if(size<=0 || size>65536) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
   IntPtr buffer=Marshal.AllocHGlobal(size);
   try {if(!GetTokenInformation(token,cls,buffer,size,out size)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    return new SecurityIdentifier(Marshal.ReadIntPtr(buffer)).Value;
   } finally {Marshal.FreeHGlobal(buffer);}
  }
  static int Integrity(IntPtr token) {string sid=TokenSid(token,25);return Int32.Parse(sid.Substring(sid.LastIndexOf('-')+1));}
  public static DllAccessResult Probe(int pid) {
   DllAccessResult result=new DllAccessResult();result.ProcessId=pid;
   IntPtr process=IntPtr.Zero, token=IntPtr.Zero;
   try {
    using(WindowsIdentity caller=WindowsIdentity.GetCurrent()) {result.CallerUserSid=caller.User.Value;result.CallerIntegrityRid=Integrity(caller.Token);result.CallerIsAdministrator=new WindowsPrincipal(caller).IsInRole(WindowsBuiltInRole.Administrator);}
    process=OpenProcess(0x043A,false,pid);result.InjectionRightsGranted=(process!=IntPtr.Zero);
    if(process==IntPtr.Zero) {result.OpenProcessError=Marshal.GetLastWin32Error();process=OpenProcess(0x1000,false,pid);}
    if(process==IntPtr.Zero) {result.Error="Cannot query target process; error "+Marshal.GetLastWin32Error();return result;}
    StringBuilder name=new StringBuilder(32768);uint size=32768;
    if(QueryFullProcessImageName(process,0,name,ref size)) result.ImagePath=name.ToString();
    else result.Error="Cannot query target image; error "+Marshal.GetLastWin32Error();
    if(OpenProcessToken(process,8,out token)) {result.TargetUserSid=TokenSid(token,1);result.TargetIntegrityRid=Integrity(token);}
    else result.Error=(result.Error??"")+" Cannot query target token; error "+Marshal.GetLastWin32Error();
    result.HigherIntegrity=result.TargetIntegrityRid>=0 && result.CallerIntegrityRid>=0 && result.TargetIntegrityRid>result.CallerIntegrityRid;
    result.DifferentUser=result.TargetUserSid!=null && result.TargetUserSid!=result.CallerUserSid;
   } catch(Exception error) {result.Error=error.Message;}
   finally {if(token!=IntPtr.Zero) CloseHandle(token);if(process!=IntPtr.Zero) CloseHandle(process);}
   return result;
  }
 }
}
'@
}

function Get-SoftwareProcessAccess {
    param([int]$ProcessId,[string]$ExpectedPath)
    if ($ProcessId -le 0) {throw 'A positive process ID is required.'}
    $ExpectedPath=Assert-LocalSoftwarePath $ExpectedPath
    Initialize-SoftwareDllNativeProbe
    $result=[HostSecurity.DllAccessV31]::Probe($ProcessId)
    $matches=$result.ImagePath -and [IO.Path]::GetFullPath($result.ImagePath) -eq $ExpectedPath
    $accessStatus=if (-not $matches) {'ImageIdentityUnavailableOrChanged'} elseif (-not $result.InjectionRightsGranted) {'AccessNotGranted'} elseif ($result.CallerIsAdministrator -or $result.CallerIntegrityRid -ge 12288) {'ElevatedCallerAccessOnly'} elseif ($result.HigherIntegrity -or $result.DifferentUser) {'SecurityBoundaryAccessCandidate'} elseif ($result.TargetIntegrityRid -lt 0 -or -not $result.TargetUserSid) {'TargetTokenUnavailable'} else {'SameSecurityContextAccess'}
    [pscustomobject]@{ProcessId=$ProcessId;ExpectedPath=$ExpectedPath;ImagePath=$result.ImagePath;ImageMatchesExpected=[bool]$matches;AccessStatus=$accessStatus;RequestedAccess=$result.RequestedAccess;InjectionRightsGranted=$result.InjectionRightsGranted;OpenProcessError=$result.OpenProcessError;CallerUserSid=$result.CallerUserSid;CallerIntegrityRid=$result.CallerIntegrityRid;CallerIsAdministrator=$result.CallerIsAdministrator;TargetUserSid=$result.TargetUserSid;TargetIntegrityRid=$result.TargetIntegrityRid;HigherIntegrity=$result.HigherIntegrity;DifferentUser=$result.DifferentUser;Error=$result.Error;Explanation='Access-handle test only; no target-process memory is read/written, no DLL is loaded and no thread is created. Cross-integrity/user access from a non-elevated caller is a review candidate. Same-user and elevated-administrator access are often expected. PID/image matching guards against process reuse; PPL, ACG/CIG, architecture, endpoint protection and execution feasibility remain untested.'}
}

function Get-SoftwareDllVerificationPlan {
    param($Data,[switch]$Injection)
    $definitions=New-Object 'System.Collections.Generic.List[string]'
    $names=if ($Injection) {@('Assert-LocalVerificationPath','Assert-LocalSoftwarePath','Initialize-SoftwareDllNativeProbe','Get-SoftwareProcessAccess')} else {@('Assert-LocalVerificationPath','Assert-LocalSoftwarePath','Read-PeInteger','Convert-PeRvaToOffset','Get-PeDllImports','Get-SoftwareDllAcl')}
    foreach ($name in $names) {$body=(Get-Item -LiteralPath ('Function:\'+$name) -ErrorAction Stop).ScriptBlock.ToString();$definitions.Add('function '+$name+" {`n"+$body+"`n}")}
    $prefix=($definitions.ToArray() -join "`n")+"`n"
    if ($Injection) {
        if (-not $Data.ProcessId -or -not $Data.BinaryPath) {throw 'Saved process ID or executable path is missing.'}
        $path=Assert-LocalSoftwarePath ([string]$Data.BinaryPath)
        New-VerificationStep 'Process injection access rights' ($prefix+'Get-SoftwareProcessAccess -ProcessId '+[int]$Data.ProcessId+' -ExpectedPath '+(ConvertTo-PowerShellLiteral $path)) 'Retests access rights and process identity without injection. Only matching image paths and a known security boundary can support this candidate; access alone does not prove execution.'
    } else {
        if (-not $Data.BinaryPath -or -not $Data.DllPath) {throw 'Saved binary or candidate DLL path is missing.'}
        $binary=Assert-LocalSoftwarePath ([string]$Data.BinaryPath)
        Assert-LocalVerificationPath ([string]$Data.DllPath) 'File'
        $dll=[IO.Path]::GetFullPath([string]$Data.DllPath)
        $command=$prefix+'Get-PeDllImports -Path '+(ConvertTo-PowerShellLiteral $binary)+"`n"+'Get-SoftwareDllAcl -Path '+(ConvertTo-PowerShellLiteral (Split-Path -Parent $dll))+"`n"+'if (Test-Path -LiteralPath '+(ConvertTo-PowerShellLiteral $dll)+') {Get-SoftwareDllAcl -Path '+(ConvertTo-PowerShellLiteral $dll)+'}'
        New-VerificationStep 'DLL import and permission review' $command 'Rechecks static/delay imports and complete selected ACL entries. Deny and inherit-only ACEs matter. A missing app-local DLL can legitimately resolve elsewhere; use a normal application load trace on a test host to establish actual lookup order. No DLL is planted or application launched.'
    }
}

function Get-InstalledSoftwareDllAssessment {
    param([object[]]$Software,[object[]]$Processes=@(),[object[]]$Services=@(),[object[]]$Tasks=@(),[int]$MaxFilesPerSoftware=20000,[int]$MaxCandidatesPerSoftware=1000,[int]$TimeoutSeconds=120,[switch]$Skip)
    $known=if ($Skip) {@()} else {@(Get-KnownSoftwareDllNames)}
    $applications=New-Object 'System.Collections.Generic.List[object]'
    $rootCache=@{};$aclCache=@{};$processCache=@{}
    foreach ($app in @($Software)) {
        $timer=[Diagnostics.Stopwatch]::StartNew();$errors=New-Object 'System.Collections.Generic.List[string]'
        $binaries=New-Object 'System.Collections.Generic.List[object]';$candidates=New-Object 'System.Collections.Generic.List[object]';$injection=New-Object 'System.Collections.Generic.List[object]'
        $root='';$rootSource='';$examined=0;$reparseSkipped=0;$status='NotAssessed';$reason='No usable installation directory or executable DisplayIcon is registered.'
        try {
            if ($Skip) {$status='Skipped';$reason='Disabled with -SkipSoftwareDllScan.'}
            else {
                $location=[Environment]::ExpandEnvironmentVariables([string]$app.InstallLocation).Trim().Trim('"')
                if ($location) {$root=Assert-LocalSoftwarePath $location;$rootSource='InstallLocation'}
                elseif ($app.DisplayIcon) {
                    $icon=[Environment]::ExpandEnvironmentVariables([string]$app.DisplayIcon) -replace ',\s*-?\d+\s*$',''
                    $icon=$icon.Trim().Trim('"')
                    if ([IO.Path]::GetExtension($icon) -eq '.exe' -and (Test-Path -LiteralPath $icon)) {$root=Split-Path -Parent (Assert-LocalSoftwarePath $icon);$rootSource='DisplayIcon executable directory (inferred)'}
                }
                if ($root) {
                    $broadRoots=@([IO.Path]::GetPathRoot($root),$env:SystemRoot,$env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramFiles(x86)'),[Environment]::GetEnvironmentVariable('ProgramW6432')) | Where-Object {$_}
                    if (@($broadRoots | Where-Object {$_.TrimEnd([char]92) -eq $root.TrimEnd([char]92)}).Count) {throw 'Installation path is an overly broad drive/Windows/Program Files root.'}
                    if (-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Registered installation directory is missing.'}
                    $status='Collected';$reason='No candidate observed in the selected static/file/process checks. This is not proof that injection or sideloading is impossible.'
                    if ($rootCache.ContainsKey($root)) {
                        $cached=$rootCache[$root];$binaries.AddRange([object[]]$cached.Binaries);$candidates.AddRange([object[]]$cached.Candidates)
                        $status=$cached.Status;$reason=$cached.Reason;$examined=$cached.Examined;$reparseSkipped=$cached.ReparseSkipped
                        foreach ($errorText in $cached.Errors) {$errors.Add($errorText)}
                    } else {
                        $queue=New-Object 'System.Collections.Generic.Queue[string]';$queue.Enqueue($root)
                        while ($queue.Count -gt 0) {
                            if ($candidates.Count -ge $MaxCandidatesPerSoftware) {$status='Partial';$reason='Candidate budget reached; remaining DLL candidates were not reviewed.';break}
                            if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds -or $examined -ge $MaxFilesPerSoftware) {$status='Partial';$reason='File/time budget reached; remaining files were not reviewed.';break}
                            $directory=$queue.Dequeue()
                            try {
                                foreach ($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
                                    if ($candidates.Count -ge $MaxCandidatesPerSoftware) {$status='Partial';$reason='Candidate budget reached; remaining DLL candidates were not reviewed.';break}
                                    if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds -or $examined -ge $MaxFilesPerSoftware) {$status='Partial';$reason='File/time budget reached; remaining files were not reviewed.';break}
                                    $examined++
                                    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {$reparseSkipped++;continue}
                                    if ($item.PSIsContainer) {$queue.Enqueue($item.FullName);continue}
                                    if ($item.Extension -notin @('.exe','.dll')) {continue}
                                    $pe=Get-PeDllImports $item.FullName;$binaries.Add($pe)
                                    if ($pe.Status -ne 'Collected') {$errors.Add($item.FullName+': '+$pe.Error);continue}
                                    if (-not $aclCache.ContainsKey($directory)) {$aclCache[$directory]=Get-SoftwareDllAcl $directory}
                                    $dirAcl=$aclCache[$directory]
                                    if ($dirAcl.Status -ne 'Collected') {$errors.Add($directory+': '+$dirAcl.Error)}
                                    $imports=@($pe.Imports)
                                    if ($item.Extension -eq '.dll') {$imports+= [pscustomobject]@{DllName=$item.Name;ImportKind='ExistingDllFile'}}
                                    foreach ($import in $imports) {
                                        if ($candidates.Count -ge $MaxCandidatesPerSoftware) {$status='Partial';$reason='Candidate budget reached; remaining DLL candidates were not reviewed.';break}
                                        $name=[string]$import.DllName
                                        # API sets and KnownDLLs are resolved before ordinary directory searches.
                                        if ($import.ImportKind -ne 'ExistingDllFile' -and ($name -match '^(api|ext)-ms-' -or $known -contains $name.ToLowerInvariant())) {continue}
                                        if ($name -notmatch '^[^\\/:\r\n]+\.dll$' -or $name -match '[<>|?*]') {continue}
                                        $dll=Join-Path $directory $name;$exists=Test-Path -LiteralPath $dll -PathType Leaf;$fileAcl=$null
                                        if ($exists) {
                                            if (-not $aclCache.ContainsKey($dll)) {$aclCache[$dll]=Get-SoftwareDllAcl $dll}
                                            $fileAcl=$aclCache[$dll]
                                            if ($fileAcl.Status -ne 'Collected') {$errors.Add($dll+': '+$fileAcl.Error)}
                                        }
                                        if (-not $dirAcl.BroadWriteAllow -and -not $fileAcl.BroadWriteAllow) {continue}
                                        $kind=if (-not $exists) {'MissingAppLocalImport'} elseif ($fileAcl.BroadWriteAllow) {'WritableExistingDll'} else {'DllParentPermissionCandidate'}
                                        $candidates.Add([pscustomobject]@{CandidateKind=$kind;BinaryPath=$item.FullName;Architecture=$pe.Architecture;DllName=$name;DllPath=$dll;ImportKind=$import.ImportKind;DllExists=$exists;DirectoryAcl=$dirAcl;DllAcl=$fileAcl;ExternalManifestPresent=(Test-Path -LiteralPath ($item.FullName+'.manifest'));Explanation='Broad applicable Allow ACE heuristic only; deny rules and effective access are not computed. Existing DLLs may be unused. For DLL importers, their folder is not necessarily the application search folder. API sets/KnownDLL imports were excluded; embedded manifests, SxS, package graphs, dynamic loads and search flags remain unresolved. Confirm the actual loader path and consuming identity before claiming sideloading or elevation.'})
                                    }
                                }
                            } catch {$errors.Add($directory+': '+$_.Exception.Message)}
                        }
                        if ($errors.Count -or $reparseSkipped) {$status='Partial';if ($reason -notmatch 'budget') {$reason='Some files/permissions could not be reviewed, or reparse points were excluded.'}}
                        if (-not $binaries.Count -and $status -eq 'Collected') {$status='NoBinaryData';$reason='No EXE/DLL files were found; dynamic/plugin and other binary types were not assessed.'}
                        $rootCache[$root]=[pscustomobject]@{Binaries=$binaries.ToArray();Candidates=$candidates.ToArray();Status=$status;Reason=$reason;Examined=$examined;ReparseSkipped=$reparseSkipped;Errors=$errors.ToArray()}
                    }
                    $prefix=$root.TrimEnd([char]92)+'\'
                    foreach ($process in @($Processes)) {
                        if (-not $process.Path -or -not ([string]$process.Path).StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) {continue}
                        try {
                            if (-not $processCache.ContainsKey([int]$process.Id)) {$processCache[[int]$process.Id]=Get-SoftwareProcessAccess -ProcessId $process.Id -ExpectedPath $process.Path}
                            $injection.Add($processCache[[int]$process.Id])
                            if ($processCache[[int]$process.Id].Error) {$errors.Add('Process '+$process.Id+': '+$processCache[[int]$process.Id].Error)}
                        } catch {$errors.Add('Process '+$process.Id+': '+$_.Exception.Message)}
                    }
                }
            }
        } catch {$status='Unavailable';$reason=$_.Exception.Message}
        if ($errors.Count -and $status -eq 'Collected') {$status='Partial';$reason='Some files, ACLs or process checks were unavailable.'}
        $consumers=@(foreach ($service in @($Services)) {if ($root -and $service.Executable -and ([string]$service.Executable).StartsWith($root.TrimEnd([char]92)+'\',[StringComparison]::OrdinalIgnoreCase)) {[pscustomobject]@{Kind='Service';Name=$service.Name;BinaryPath=$service.Executable;RunAs=$service.StartName;StartMode=$service.StartMode}}};foreach ($task in @($Tasks)) {if ($root -and $task.Action -and ([string]$task.Action).StartsWith($root.TrimEnd([char]92)+'\',[StringComparison]::OrdinalIgnoreCase)) {[pscustomobject]@{Kind='Task';Name=$task.TaskPath+$task.TaskName;BinaryPath=$task.Action;RunAs=$task.RunAs;GroupId=$task.GroupId;RunLevel=$task.RunLevel;Enabled=$task.Enabled}}})
        foreach ($candidate in $candidates) {
            $evidence=[pscustomobject]@{Software=$app.DisplayName;Version=$app.DisplayVersion;InstallRoot=$root;CandidateKind=$candidate.CandidateKind;BinaryPath=$candidate.BinaryPath;DllPath=$candidate.DllPath;Candidate=$candidate;Consumers=@($consumers | Where-Object BinaryPath -eq $candidate.BinaryPath)}
            try {$plan=@(Get-SoftwareDllVerificationPlan $evidence);$command=$plan[0].Command} catch {$command='# Verification plan unavailable: '+$_.Exception.Message;$errors.Add($command);$status='Partial'}
            Add-Finding 'Medium' 'DLL Security' "Installed software DLL loading candidate: $($app.DisplayName) / $([IO.Path]::GetFileName($candidate.BinaryPath)) -> $($candidate.DllName)" 'Review' $candidate.Explanation 'Review full DACLs and effective replacement/creation access. Trace normal DLL loads on a test host and verify application identity, search flags/manifests and application-control policy before concluding exploitability.' -Command $command -EvidenceData $evidence -VerificationSteps $command -Reference 'https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order'
        }
        $boundaryAccess=@($injection | Where-Object {$_.ImageMatchesExpected -and $_.InjectionRightsGranted -and -not $_.CallerIsAdministrator -and $_.CallerIntegrityRid -ge 0 -and $_.CallerIntegrityRid -lt 12288 -and ($_.HigherIntegrity -or $_.DifferentUser)})
        foreach ($access in $boundaryAccess) {
            $evidence=[pscustomobject]@{Software=$app.DisplayName;Version=$app.DisplayVersion;BinaryPath=$access.ExpectedPath;ProcessId=$access.ProcessId;AccessProbe=$access}
            try {$plan=@(Get-SoftwareDllVerificationPlan $evidence -Injection);$command=$plan[0].Command} catch {$command='# Verification plan unavailable: '+$_.Exception.Message;$errors.Add($command);$status='Partial'}
            $severity=if ($access.HigherIntegrity) {'High'} else {'Medium'}
            Add-Finding $severity 'DLL Security' "Installed software process injection access: $($app.DisplayName) / PID $($access.ProcessId)" 'Review' $access.Explanation 'Repeat non-elevated and validate target identity and granted access. Review process security, mitigations and endpoint controls. Obtaining a process handle does not confirm injection or code execution.' -Command $command -EvidenceData $evidence -VerificationSteps $command -Reference 'https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights'
        }
        $injectionStatus=if ($Skip) {'Skipped'} elseif (-not $root -or $status -eq 'Unavailable') {'NotAssessed'} elseif ($injection.Count) {'AccessChecksRecorded'} elseif (@($errors | Where-Object {$_ -match '^Process '}).Count) {'Unavailable'} else {'NoMatchingVisibleRunningProcess'}
        if ($candidates.Count -or $boundaryAccess.Count) {
            $coverageNote=if ($reason -match '^No candidate observed') {''} else {' '+$reason}
            $reason=('{0} DLL and {1} process-access candidates require review; execution and privilege escalation remain unconfirmed.' -f $candidates.Count,$boundaryAccess.Count)+$coverageNote
        }
        $outcome=if ($Skip) {'Skipped'} elseif ($candidates.Count -or $boundaryAccess.Count) {'CandidatesForReview'} elseif ($status -ne 'Collected') {'IncompleteOrNotAssessed'} else {'NoCandidateObservedNotAPass'}
        $applications.Add([pscustomobject]@{Software=$app.DisplayName;Version=$app.DisplayVersion;Publisher=$app.Publisher;InventorySource=$app.InventorySource;InstallRoot=$root;RootSource=$rootSource;Status=$status;ReviewOutcome=$outcome;Explanation=$reason;EntriesExamined=$examined;BinaryCount=$binaries.Count;ReparsePointsSkipped=$reparseSkipped;DllCandidateCount=$candidates.Count;DllCandidates=$candidates.ToArray();BinaryImports=$binaries.ToArray();RegisteredConsumers=$consumers;InjectionStatus=$injectionStatus;ProcessAccessCandidateCount=$boundaryAccess.Count;ProcessAccessChecks=$injection.ToArray();Errors=$errors.ToArray();DurationMilliseconds=$timer.ElapsedMilliseconds})
    }
    [ordered]@{Overview=[pscustomobject]@{ApplicationsInventoried=@($Software).Count;ApplicationRows=$applications.Count;RootsWithBinaryData=@($applications | Where-Object BinaryCount -gt 0).Count;IncompleteApplications=@($applications | Where-Object Status -ne 'Collected').Count;ProcessesWithoutVisiblePath=@($Processes | Where-Object {-not $_.Path}).Count;MaxEntriesPerSoftware=$MaxFilesPerSoftware;MaxCandidatesPerSoftware=$MaxCandidatesPerSoftware;SecondsPerSoftware=$TimeoutSeconds;Skipped=[bool]$Skip;Scope='Machine/current-user uninstall entries and available AppX/MSIX inventory. Portable software and unloaded user profiles may be absent. No app is launched, DLL is created, process memory accessed or privilege enabled. No candidate observed is not a security pass.'};KnownDllNames=$known;Applications=$applications.ToArray()}
}


function Set-ReportProperty {
    param($Target, [string]$Name, $Value)
    # Fresh scans use dictionaries; imported JSON uses PSCustomObject.
    if ($Target -is [System.Collections.IDictionary]) { $Target[$Name] = $Value }
    else { $Target | Add-Member NoteProperty $Name $Value -Force }
}

function Update-AssessmentVerification {
    param($Assessment, [switch]$RunVerification, [ValidateRange(1,300)][int]$TimeoutSeconds=30)
    $ErrorActionPreference='Stop'
    if ($null -eq $Assessment.Metadata -or $null -eq $Assessment.Findings) {
        throw 'Input is not an assessment report with Metadata and Findings.'
    }
    if ($RunVerification -and ([string]::IsNullOrWhiteSpace([string]$Assessment.Metadata.Host) -or
        [string]$Assessment.Metadata.Host -ne $env:COMPUTERNAME)) {
        throw 'RunVerification must run on the original scanned host (Metadata.Host must match COMPUTERNAME).'
    }
    Set-ReportProperty $Assessment.Metadata 'VerificationStepsAddedAt' ((Get-Date).ToString('o'))
    Set-ReportProperty $Assessment.Metadata 'VerificationRendererVersion' '3.1'
    if ($RunVerification) {
        $Identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $Principal=[Security.Principal.WindowsPrincipal]::new($Identity)
            $Execution=[pscustomobject]@{
                Host=$env:COMPUTERNAME;User=$Identity.Name;UserSid=$Identity.User.Value
                IsAdministrator=$Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                PowerShellVersion=[string]$PSVersionTable.PSVersion;StartedAt=(Get-Date).ToString('o')
                CompletedAt=$null;TimeoutSeconds=$TimeoutSeconds;EngineVersion='3.1'
            }
        } finally {$Identity.Dispose()}
        Set-ReportProperty $Assessment.Metadata 'VerificationExecution' $Execution
    }
    $Index=0
    try {
        foreach ($Finding in @($Assessment.Findings)) {
            $Steps=Get-FindingVerificationSteps -Title $Finding.Finding -Category $Finding.Category -EvidenceData $Finding.EvidenceData -Command $Finding.Command
            Set-ReportProperty $Finding 'VerificationSteps' $Steps
            if ($RunVerification) {
                $Index++
                Write-Progress -Activity 'Verifying report findings locally' -Status $Finding.Finding -PercentComplete (100*$Index/[Math]::Max(1,@($Assessment.Findings).Count))
                $Result=Invoke-FindingVerification -Finding $Finding -TimeoutSeconds $TimeoutSeconds
                Set-ReportProperty $Result 'ExecutionContext' ([pscustomobject]@{
                    Host=$Execution.Host;User=$Execution.User;UserSid=$Execution.UserSid;IsAdministrator=$Execution.IsAdministrator
                })
                Set-ReportProperty $Finding 'VerificationResult' $Result
                if ($Result.Steps.Count) {
                    $Commands=@($Result.Steps | ForEach-Object {'# '+$_.Name+"`n"+$_.Command}) -join "`n`n"
                    Set-ReportProperty $Finding 'VerificationSteps' $Commands
                }
            }
        }
    } finally {
        if ($RunVerification) {Write-Progress -Activity 'Verifying report findings locally' -Completed}
    }
    if ($RunVerification) {$Execution.CompletedAt=(Get-Date).ToString('o')}
}

function ConvertTo-AssessmentDictionary {
    param($Value)
    $Copy=[ordered]@{}
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($Key in $Value.Keys) {$Copy[$Key]=$Value[$Key]}
    } elseif ($null -ne $Value) {
        foreach ($Property in $Value.PSObject.Properties) {$Copy[$Property.Name]=$Property.Value}
    }
    return $Copy
}

function Get-AssessmentSeveritySummary {
    param([object[]]$Findings)
    $Counts=[ordered]@{}
    foreach ($Severity in @('Critical','High','Medium','Low','Informational')) {
        $Counts[$Severity]=@($Findings | Where-Object Severity -eq $Severity).Count
    }
    $Counts.Total=@($Findings).Count
    return $Counts
}

function Split-AssessmentDllReport {
    param([System.Collections.IDictionary]$Assessment)
    if ($Assessment.Metadata.ReportKind -eq 'DllAnalysis') {
        return [pscustomobject]@{HostReport=$null;DllReport=$Assessment}
    }
    $DllFindings=@($Assessment.Findings | Where-Object {
        $_.Category -eq 'DLL Security' -or $_.Finding -like 'Installed software DLL loading candidate:*' -or
        $_.Finding -like 'Installed software process injection access:*'
    })
    if (-not $Assessment.Contains('SoftwareDllAssessment') -and $DllFindings.Count -eq 0) {
        return [pscustomobject]@{HostReport=$Assessment;DllReport=$null}
    }
    $DllMetadata=ConvertTo-AssessmentDictionary $Assessment.Metadata
    $DllMetadata.ReportKind='DllAnalysis'
    $DllReport=[ordered]@{
        Metadata=$DllMetadata
        SeveritySummary=(Get-AssessmentSeveritySummary $DllFindings)
        Findings=$DllFindings
        SoftwareDllAssessment=$Assessment.SoftwareDllAssessment
    }
    # Partition findings before verification and serialization; no DLL payload stays in the host DOM.
    $Assessment.Findings=@($Assessment.Findings | Where-Object {
        $_.Category -ne 'DLL Security' -and $_.Finding -notlike 'Installed software DLL loading candidate:*' -and
        $_.Finding -notlike 'Installed software process injection access:*'
    })
    $Assessment.Remove('SoftwareDllAssessment')
    $Assessment.SeveritySummary=Get-AssessmentSeveritySummary $Assessment.Findings
    Set-ReportProperty $Assessment.Metadata 'ReportKind' 'HostAssessment'
    return [pscustomobject]@{HostReport=$Assessment;DllReport=$DllReport}
}

function New-DllListingHtml {
    param([string]$Title,[object[]]$Rows,[string]$Navigation,[string]$Description)
    $Body=New-Object Text.StringBuilder
    foreach ($Row in $Rows) {
        [void]$Body.Append('<tr data-rank="'+[int]$Row.Rank+'"><td>'+ (ConvertTo-HtmlText $Row.Severity) +
            '</td><td><a href="'+(ConvertTo-HtmlText $Row.Link)+'">'+(ConvertTo-HtmlText $Row.Subject)+
            '</a></td><td>'+(ConvertTo-HtmlText $Row.Status)+'</td></tr>')
    }
    $TitleText=ConvertTo-HtmlText $Title
    $DescriptionText=ConvertTo-HtmlText $Description
    $Script=@'
<script>
(() => {
  const table=document.querySelector('table'), body=table.tBodies[0], heads=Array.from(table.tHead.rows[0].cells);
  let column=0, ascending=true;
  const rows=()=>Array.from(body.rows);
  function sort(i,up) {
    rows().sort((a,b)=>{const result=i===0?Number(a.dataset.rank)-Number(b.dataset.rank):a.cells[i].textContent.localeCompare(b.cells[i].textContent,undefined,{numeric:true});return up?result:-result;}).forEach(r=>body.appendChild(r));
    heads.forEach((h,n)=>h.setAttribute('aria-sort',n===i?(up?'ascending':'descending'):'none'));
    column=i;ascending=up;
  }
  heads.forEach((h,i)=>h.querySelector('button').addEventListener('click',()=>sort(i,i===column?!ascending:true)));
  document.querySelector('input').addEventListener('input',e=>rows().forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(e.target.value.toLowerCase())));
  sort(0,true);
})();
</script>
'@
    return @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>$TitleText</title>
<style>body{font:15px/1.6 'Segoe UI',sans-serif;color:#172b4d;background:#f2f5f9;margin:0}main{max-width:1200px;margin:auto;padding:28px}a{color:#175cad}nav{display:flex;gap:16px;flex-wrap:wrap}details{background:white;padding:18px;border:1px solid #dbe3ed;border-radius:8px;margin-top:20px}summary{cursor:pointer;font-weight:bold}table{border-collapse:collapse;width:100%}td,th{padding:12px;text-align:left;border-bottom:1px solid #dbe3ed;overflow-wrap:anywhere}button,input{font:inherit;padding:6px}th button{border:0;background:transparent;cursor:pointer}th[aria-sort=ascending] button:after{content:' ▲'}th[aria-sort=descending] button:after{content:' ▼'}input{margin:16px 0;max-width:90%}tr[data-rank="0"] td:first-child,tr[data-rank="1"] td:first-child{color:#a31525;font-weight:bold}.scroll{overflow:auto}</style></head>
<body><main><h1>$TitleText</h1><nav>$Navigation</nav><p>$DescriptionText</p>
<details open><summary>Report entries ($(@($Rows).Count))</summary><label>Filter this page <input type="search" placeholder="Search entries"></label><div class="scroll"><table><thead><tr><th aria-sort="ascending"><button>Severity</button></th><th aria-sort="none"><button>Finding / application / page</button></th><th aria-sort="none"><button>Status</button></th></tr></thead><tbody>$Body</tbody></table></div></details>$Script</main></body></html>
"@
}

function Export-DllAssessmentReport {
    param([System.Collections.IDictionary]$Assessment,[string]$OutputDirectory,[string]$BaseName,[string]$HostHtmlName)
    $ErrorActionPreference='Stop'
    $Files=New-Object 'System.Collections.Generic.List[string]'
    $DetailName=$BaseName+'_Details'
    $DetailPath=Join-Path $OutputDirectory $DetailName
    New-Item -ItemType Directory -Path $DetailPath -Force | Out-Null
    $IndexName=$BaseName+'.html'
    $IndexLink='../'+[uri]::EscapeDataString($IndexName)
    $DetailLink=[uri]::EscapeDataString($DetailName)+'/'
    $Ranks=@{Critical=0;High=1;Medium=2;Low=3;Informational=4}
    $Findings=@($Assessment.Findings | Sort-Object @{Expression={$Ranks[$_.Severity]}},Category,Finding)
    $FindingRows=New-Object 'System.Collections.Generic.List[object]'
    for ($i=0;$i -lt $Findings.Count;$i++) {
        $Finding=$Findings[$i];$Name='finding-{0:D6}.html' -f ($i+1)
        $Detail=[ordered]@{Metadata=$Assessment.Metadata;SeveritySummary=(Get-AssessmentSeveritySummary @($Finding));Findings=@($Finding)}
        $Path=Join-Path $DetailPath $Name
        New-AssessmentHtml $Detail -Title 'DLL finding evidence' -ReportLink $IndexLink -LinkLabel 'DLL analysis index' | Set-Content -LiteralPath $Path -Encoding UTF8
        $Files.Add($Path)
        $FindingRows.Add([pscustomobject]@{Rank=$Ranks[$Finding.Severity];Severity=$Finding.Severity;Subject=$Finding.Finding;Status=$Finding.Status;Link=$Name})
    }
    $AppRows=New-Object 'System.Collections.Generic.List[object]'
    $AppIndex=0
    foreach ($App in @($Assessment.SoftwareDllAssessment.Applications | Where-Object {$null -ne $_})) {
        $AppIndex++;$Prefix='application-{0:D6}' -f $AppIndex
        $AllAppData=ConvertTo-AssessmentDictionary $App
        $AppData=ConvertTo-AssessmentDictionary $App
        foreach ($Key in @('BinaryImports','DllCandidates','ProcessAccessChecks','RegisteredConsumers','Errors')) {$AppData.Remove($Key)}
        $ChunkRows=New-Object 'System.Collections.Generic.List[object]'
        foreach ($Key in @('BinaryImports','DllCandidates','ProcessAccessChecks','RegisteredConsumers','Errors')) {
            $Entries=@($AllAppData[$Key] | Where-Object {$null -ne $_})
            # Only 25 records enter each detail DOM. Full exports retain every record.
            for ($Offset=0;$Offset -lt $Entries.Count;$Offset+=25) {
                $Last=[Math]::Min($Offset+24,$Entries.Count-1)
                $Name=$Prefix+'-'+$Key+'-'+([int]($Offset/25)+1)+'.html'
                $Detail=[ordered]@{Metadata=$Assessment.Metadata;SeveritySummary=(Get-AssessmentSeveritySummary @());Findings=@();Application=$AppData}
                $Detail[$Key]=@($Entries[$Offset..$Last])
                $Path=Join-Path $DetailPath $Name
                New-AssessmentHtml $Detail -Title ($App.Software+' / '+$Key+' / records '+($Offset+1)+'–'+($Last+1)) -ReportLink ($Prefix+'.html') -LinkLabel 'Application summary' | Set-Content -LiteralPath $Path -Encoding UTF8
                $Files.Add($Path)
                $ChunkRows.Add([pscustomobject]@{Rank=4;Severity='';Subject=$Key+' / records '+($Offset+1)+'–'+($Last+1);Status='Saved evidence';Link=$Name})
            }
        }
        $SummaryHtml=ConvertTo-ReportValueHtml $AppData
        $Nav='<a href="'+(ConvertTo-HtmlText $IndexLink)+'">DLL analysis index</a>'
        $AppHtml=New-DllListingHtml -Title ($App.Software+' / application evidence') -Rows $ChunkRows.ToArray() -Navigation $Nav -Description 'Open a record page for saved imports, permission candidates, process access or collection errors. No evidence records were truncated.'
        $AppHtml=$AppHtml.Replace('</main>','<details><summary>Application summary</summary>'+ $SummaryHtml+'</details></main>')
        $Path=Join-Path $DetailPath ($Prefix+'.html');$AppHtml | Set-Content -LiteralPath $Path -Encoding UTF8;$Files.Add($Path)
        $AppRows.Add([pscustomobject]@{Rank=4;Severity='';Subject=$App.Software;Status=$App.Status;Link=$Prefix+'.html'})
    }
    $LandingRows=New-Object 'System.Collections.Generic.List[object]'
    foreach ($List in @([pscustomobject]@{Name='findings';Rows=$FindingRows.ToArray()},[pscustomobject]@{Name='applications';Rows=$AppRows.ToArray()})) {
        $PageCount=[int][Math]::Ceiling($List.Rows.Count/100.0)
        for ($Page=0;$Page -lt $PageCount;$Page++) {
            $Start=$Page*100;$Last=[Math]::Min($Start+99,$List.Rows.Count-1)
            $Name=$List.Name+'-'+($Page+1)+'.html'
            $Nav='<a href="'+(ConvertTo-HtmlText $IndexLink)+'">DLL analysis index</a>'
            if ($Page -gt 0) {$Nav+=' <a href="'+$List.Name+'-'+$Page+'.html">Previous page</a>'}
            if ($Page+1 -lt $PageCount) {$Nav+=' <a href="'+$List.Name+'-'+($Page+2)+'.html">Next page</a>'}
            $Path=Join-Path $DetailPath $Name
            New-DllListingHtml -Title ('DLL '+$List.Name+' / page '+($Page+1)+' of '+$PageCount) -Rows @($List.Rows[$Start..$Last]) -Navigation $Nav -Description 'Click an entry to open its full evidence. Finding pages are ordered by severity across pages; sorting and filtering apply to this page.' | Set-Content -LiteralPath $Path -Encoding UTF8
            $Files.Add($Path)
            $LandingRows.Add([pscustomobject]@{Rank=4;Severity='';Subject=$List.Name+' / '+($Start+1)+'–'+($Last+1)+' of '+$List.Rows.Count;Status='Open list';Link=$DetailLink+$Name})
        }
    }
    foreach ($Extension in @('json','txt')) {
        $Path=Join-Path $OutputDirectory ($BaseName+'.'+$Extension)
        if ($Extension -eq 'json') {ConvertTo-Json -InputObject $Assessment -Depth 100 -WarningAction Stop | Set-Content -LiteralPath $Path -Encoding UTF8}
        else {New-AssessmentText $Assessment | Set-Content -LiteralPath $Path -Encoding UTF8}
        $Files.Add($Path)
    }
    $Nav='<a href="'+[uri]::EscapeDataString($BaseName+'.json')+'">Full JSON evidence</a> <a href="'+[uri]::EscapeDataString($BaseName+'.txt')+'">Full TXT evidence</a>'
    if ($HostHtmlName) {$Nav+=' <a href="'+[uri]::EscapeDataString($HostHtmlName)+'">Host security report</a>'}
    $IndexHtml=New-DllListingHtml -Title 'DLL injection / sideloading analysis' -Rows $LandingRows.ToArray() -Navigation $Nav -Description ($Findings.Count.ToString()+' review findings; '+$AppRows.Count+' inventoried application rows. Candidates require verification and do not prove exploitation. HTML evidence is split into small pages to limit browser rendering work. Keep the Details folder alongside this report.')
    $Overview=[ordered]@{Metadata=$Assessment.Metadata;SeveritySummary=$Assessment.SeveritySummary;Overview=$Assessment.SoftwareDllAssessment.Overview;KnownDllNames=$Assessment.SoftwareDllAssessment.KnownDllNames}
    $IndexHtml=$IndexHtml.Replace('</main>','<details><summary>Collection overview and severity counts</summary>'+ (ConvertTo-ReportValueHtml $Overview)+'</details></main>')
    $Path=Join-Path $OutputDirectory $IndexName;$IndexHtml | Set-Content -LiteralPath $Path -Encoding UTF8;$Files.Add($Path)
    $Manifest=Join-Path $OutputDirectory ($BaseName+'_SHA256.txt')
    $Hashes=foreach ($File in $Files) {'{0}  {1}' -f (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash,$File.Substring($OutputDirectory.TrimEnd('\').Length+1)}
    $Hashes | Set-Content -LiteralPath $Manifest -Encoding UTF8;$Files.Add($Manifest)
    return $Files.ToArray()
}

function Export-AssessmentReports {
    param([System.Collections.IDictionary]$Assessment,[string]$OutputDirectory,[string]$BaseName,[switch]$RunVerification,[int]$TimeoutSeconds=30)
    $ErrorActionPreference='Stop'
    $Split=Split-AssessmentDllReport $Assessment
    # Verify both partitions before writing any reports. Existing transcripts stay with their finding.
    foreach ($Part in @($Split.HostReport,$Split.DllReport)) {
        if ($null -ne $Part) {Update-AssessmentVerification -Assessment $Part -RunVerification:$RunVerification -TimeoutSeconds $TimeoutSeconds}
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $DllFiles=@();$HostFiles=@()
    $HostHtmlName=if ($null -ne $Split.HostReport) {$BaseName+'.html'} else {''}
    if ($null -ne $Split.DllReport) {
        $DllBase=if ($null -ne $Split.HostReport) {$BaseName+'_DllAnalysis'} else {$BaseName}
        $DllFiles=@(Export-DllAssessmentReport $Split.DllReport $OutputDirectory $DllBase $HostHtmlName)
    }
    if ($null -ne $Split.HostReport) {
        $HostFiles=@('json','txt','html') | ForEach-Object {Join-Path $OutputDirectory ($BaseName+'.'+$_)}
        $Link=if ($DllFiles.Count) {[uri]::EscapeDataString($BaseName+'_DllAnalysis.html')} else {''}
        if ($Link) {Set-ReportProperty $Split.HostReport.Metadata 'DllAnalysisReport' ($BaseName+'_DllAnalysis.html')}
        ConvertTo-Json -InputObject $Split.HostReport -Depth 100 -WarningAction Stop | Set-Content -LiteralPath $HostFiles[0] -Encoding UTF8
        New-AssessmentText $Split.HostReport | Set-Content -LiteralPath $HostFiles[1] -Encoding UTF8
        New-AssessmentHtml $Split.HostReport -ReportLink $Link | Set-Content -LiteralPath $HostFiles[2] -Encoding UTF8
        $Hashes=foreach ($File in @($HostFiles)+@($DllFiles)) {'{0}  {1}' -f (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash,$File.Substring($OutputDirectory.TrimEnd('\').Length+1)}
        $Hashes | Set-Content -LiteralPath (Join-Path $OutputDirectory ($BaseName+'_SHA256.txt')) -Encoding UTF8
        Write-Host ('Host report: '+$HostFiles[2])
    }
    if ($DllFiles.Count) {Write-Host ('DLL analysis: '+(Join-Path $OutputDirectory ($DllBase+'.html')))}
}

function Update-AssessmentReport {
    param([string]$InputJson, [string]$OutputDirectory, [switch]$RunVerification, [ValidateRange(1,300)][int]$TimeoutSeconds=30)
    $ErrorActionPreference='Stop'
    $InputPath=(Resolve-Path -LiteralPath $InputJson -ErrorAction Stop).Path
    $InputObject=Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
    if ($null -eq $InputObject.Metadata -or $null -eq $InputObject.Findings) {
        throw 'Input is not an assessment report with Metadata and Findings.'
    }
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $OutputDirectory=Join-Path (Split-Path $InputPath -Parent) 'with_verification'
    }
    $OutputPath=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    $BaseName=[IO.Path]::GetFileNameWithoutExtension($InputPath)
    $Files=@('json','txt','html') | ForEach-Object {Join-Path $OutputPath ($BaseName+'.'+$_)}
    if ($Files[0] -eq $InputPath) {throw 'Output must be separate from the original report.'}
    Set-ReportProperty $InputObject.Metadata 'SourceReport' ([IO.Path]::GetFileName($InputPath))
    $RefreshedReport=ConvertTo-AssessmentDictionary $InputObject
    Export-AssessmentReports $RefreshedReport $OutputPath $BaseName -RunVerification:$RunVerification -TimeoutSeconds $TimeoutSeconds
    Write-Host 'Source scan evidence and collection results are preserved. DLL findings are separated and each report has its own severity counts.'
    if ($RunVerification) {Write-Host 'Fresh verification transcripts and explanations are included. Check errors and caller identity before interpreting results.'}
    else {Write-Host 'No verification commands were executed during this refresh. Use -RunVerification to collect fresh results.'}
}

# Refresh mode returns before initialization or host collectors.
if ($PSCmdlet.ParameterSetName -eq 'Refresh') {
    Update-AssessmentReport -InputJson $InputJson -OutputDirectory $OutputDirectory -RunVerification:$RunVerification -TimeoutSeconds $TimeoutSeconds
    return
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {$OutputDirectory='.\HostSecurityReport'}

$StartTime    = Get-Date
$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$ComputerName = $env:COMPUTERNAME

if (-not (Test-Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
}

$OutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory -ErrorAction Stop).Path

$JsonFile = Join-Path $OutputDirectory "$ComputerName`_SecurityAssessment_$Timestamp.json"
$TxtFile  = Join-Path $OutputDirectory "$ComputerName`_SecurityAssessment_$Timestamp.txt"
$HtmlFile = Join-Path $OutputDirectory "$ComputerName`_SecurityAssessment_$Timestamp.html"
$HashFile = Join-Path $OutputDirectory "$ComputerName`_SecurityAssessment_$Timestamp`_SHA256.txt"

$Findings = @()
$Errors   = @()

$IsAdmin = Test-IsAdministrator

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Windows Comprehensive Security Assessment" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host " Host:      $ComputerName"
Write-Host " User:      $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host " Elevated:  $IsAdmin"
Write-Host " Output:    $OutputDirectory"
Write-Host ""

if (-not $IsAdmin) {

    Write-Warning `
        "The session is not elevated. Some security configuration will be inaccessible."
}

# ============================================================================
# SYSTEM
# ============================================================================

Write-Host "[+] System and OS"

$OS = Invoke-SafeCommand "OperatingSystem" {

    Get-CimInstance Win32_OperatingSystem |
    Select-Object `
        Caption,
        Version,
        BuildNumber,
        OSArchitecture,
        InstallDate,
        LastBootUpTime,
        WindowsDirectory,
        SystemDirectory,
        DataExecutionPrevention_Available,
        DataExecutionPrevention_SupportPolicy
}

$ComputerSystem = Invoke-SafeCommand "ComputerSystem" {

    Get-CimInstance Win32_ComputerSystem |
    Select-Object `
        Manufacturer,
        Model,
        Domain,
        DomainRole,
        PartOfDomain,
        SystemType,
        TotalPhysicalMemory
}

$BIOS = Invoke-SafeCommand "BIOS" {

    Get-CimInstance Win32_BIOS |
    Select-Object `
        Manufacturer,
        SMBIOSBIOSVersion,
        ReleaseDate
}

$Processor = Invoke-SafeCommand "Processor" {

    Get-CimInstance Win32_Processor |
    Select-Object `
        Name,
        NumberOfCores,
        NumberOfLogicalProcessors
}

$WindowsFeatureSummary = Invoke-SafeCommand "WindowsFeatures" {

    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {

        Get-WindowsFeature |
        Where-Object Installed |
        Select-Object `
            Name,
            DisplayName,
            FeatureType
    }
}

$BootConfig = Invoke-SafeCommand "BCD" {

    bcdedit.exe /enum 2>&1
}

# ============================================================================
# IDENTITY / ACCOUNT ENUMERATION
# ============================================================================

Write-Host "[+] Identity / accounts / privileges"

$CurrentIdentity = [PSCustomObject]@{

    User            = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Administrator   = $IsAdmin
    Authentication  = [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
}

$WhoAmIPrivileges = Invoke-SafeCommand "WhoAmIPrivileges" {

    whoami.exe /priv 2>&1
}

$WhoAmIGroups = Invoke-SafeCommand "WhoAmIGroups" {

    whoami.exe /groups 2>&1
}

$LocalUsers = Invoke-SafeCommand "LocalUsers" {

    Get-LocalUser |
    Select-Object `
        Name,
        SID,
        Enabled,
        LastLogon,
        PasswordRequired,
        PasswordExpires,
        UserMayChangePassword,
        PasswordLastSet,
        AccountExpires,
        Description
}

$LocalGroups = Invoke-SafeCommand "LocalGroups" {

    Get-LocalGroup |
    Select-Object Name, Description
}

$LocalAdministrators = Invoke-SafeCommand "Administrators" {

    Get-LocalGroupMember `
        -SID 'S-1-5-32-544' |
    Select-Object `
        Name,
        ObjectClass,
        PrincipalSource
}

# ============================================================================
# SECURITY POLICY
# ============================================================================

Write-Host "[+] Local security policy"

$SecurityPolicyFile = Join-Path `
    $env:TEMP `
    ("security_" + [guid]::NewGuid().ToString("N") + ".inf")

$SecurityPolicy = @{}

try {

    secedit.exe `
        /export `
        /cfg $SecurityPolicyFile `
        /quiet |
    Out-Null

    if ($LASTEXITCODE -ne 0) { throw "secedit export failed with exit code $LASTEXITCODE" }

    if (Test-Path -LiteralPath $SecurityPolicyFile) {

        foreach ($Line in Get-Content $SecurityPolicyFile) {

            if (
                $Line -match `
                "^\s*([^;][^=]+?)\s*=\s*(.*?)\s*$"
            ) {

                $SecurityPolicy[
                    $Matches[1].Trim()
                ] = $Matches[2].Trim()
            }
        }

        Remove-Item `
            $SecurityPolicyFile `
            -Force
    }
}
catch {

    Add-CollectionError `
        "SecurityPolicy" `
        $_.Exception.Message
}

$PasswordPolicy = [PSCustomObject]@{

    MinimumPasswordAge =
        $SecurityPolicy["MinimumPasswordAge"]

    MaximumPasswordAge =
        $SecurityPolicy["MaximumPasswordAge"]

    MinimumPasswordLength =
        $SecurityPolicy["MinimumPasswordLength"]

    PasswordComplexity =
        $SecurityPolicy["PasswordComplexity"]

    PasswordHistorySize =
        $SecurityPolicy["PasswordHistorySize"]

    ClearTextPassword =
        $SecurityPolicy["ClearTextPassword"]

    LockoutBadCount =
        $SecurityPolicy["LockoutBadCount"]

    ResetLockoutCount =
        $SecurityPolicy["ResetLockoutCount"]

    LockoutDuration =
        $SecurityPolicy["LockoutDuration"]
}

$UserRights = @()

foreach ($Key in $SecurityPolicy.Keys) {

    if (
        $Key -match "^Se[A-Za-z]+Privilege$" -or
        $Key -match "^Se[A-Za-z]+LogonRight$"
    ) {

        $UserRights += [PSCustomObject]@{
            Right     = $Key
            Principals = $SecurityPolicy[$Key]
        }
    }
}

# ============================================================================
# PRIVILEGED USER RIGHTS
# ============================================================================

$DangerousPrivileges = @(
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeTcbPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeLoadDriverPrivilege",
    "SeCreateTokenPrivilege",
    "SeTrustedCredManAccessPrivilege"
)

foreach ($Privilege in $DangerousPrivileges) {

    $Entry = $UserRights |
        Where-Object Right -eq $Privilege

    if ($Entry) {

        Add-Finding `
            "Informational" `
            "Privilege Management" `
            "Sensitive user right configured: $Privilege" `
            "Review" `
            "$($Entry.Principals)" `
            "Confirm this privilege is restricted to accounts that operationally require it." `
        -Command '$p = Join-Path $env:TEMP (''security-review-'' + [guid]::NewGuid() + ''.inf'')
try {
    secedit.exe /export /cfg $p /quiet
    if ($LASTEXITCODE -ne 0) { throw "secedit export failed: $LASTEXITCODE" }
    Get-Content -LiteralPath $p
} finally { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p } }' -EvidenceData ($Entry)
    }
}

# ============================================================================
# UAC
# ============================================================================

Write-Host "[+] UAC"

$UacPath = `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

$UAC = [PSCustomObject]@{

    EnableLUA =
        Get-RegistryValue $UacPath "EnableLUA"

    ConsentPromptBehaviorAdmin =
        Get-RegistryValue $UacPath "ConsentPromptBehaviorAdmin"

    ConsentPromptBehaviorUser =
        Get-RegistryValue $UacPath "ConsentPromptBehaviorUser"

    PromptOnSecureDesktop =
        Get-RegistryValue $UacPath "PromptOnSecureDesktop"

    FilterAdministratorToken =
        Get-RegistryValue $UacPath "FilterAdministratorToken"

    LocalAccountTokenFilterPolicy =
        Get-RegistryValue $UacPath "LocalAccountTokenFilterPolicy"

    EnableInstallerDetection =
        Get-RegistryValue $UacPath "EnableInstallerDetection"
}

if ($null -ne $UAC.EnableLUA -and $UAC.EnableLUA -eq 0) {

    Add-Finding `
        "High" `
        "Privilege Management" `
        "User Account Control is disabled" `
        "Fail" `
        "EnableLUA = $($UAC.EnableLUA)" `
        "Enable UAC unless there is a documented and approved exception." `
        -Command (Get-RegistryReviewCommand $UacPath @('EnableLUA')) -EvidenceData ($UAC)
}

if ($UAC.LocalAccountTokenFilterPolicy -eq 1) {

    Add-Finding `
        "Medium" `
        "Privilege Management" `
        "Remote UAC restrictions are disabled for local administrators" `
        "Review" `
        "LocalAccountTokenFilterPolicy = 1" `
        "Confirm remote full-token access for local administrators is required." `
        -Command (Get-RegistryReviewCommand $UacPath @('LocalAccountTokenFilterPolicy')) -EvidenceData ($UAC)
}

# ============================================================================
# ALWAYS INSTALL ELEVATED
# ============================================================================

Write-Host "[+] Windows Installer policy"

$AlwaysInstallElevatedHKLM = Get-RegistryValue `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    "AlwaysInstallElevated"

$AlwaysInstallElevatedHKCU = Get-RegistryValue `
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
    "AlwaysInstallElevated"

$AlwaysInstallElevated = [PSCustomObject]@{

    HKLM = $AlwaysInstallElevatedHKLM
    HKCU = $AlwaysInstallElevatedHKCU
}

if (
    $AlwaysInstallElevatedHKLM -eq 1 -and
    $AlwaysInstallElevatedHKCU -eq 1
) {

    Add-Finding `
        "High" `
        "Privilege Management" `
        "AlwaysInstallElevated is enabled" `
        "Fail" `
        "HKLM=1; HKCU=1" `
        "Disable AlwaysInstallElevated in both machine and user policy." `
        -Command 'Get-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer'' -Name AlwaysInstallElevated
Get-ItemProperty -LiteralPath ''HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'' -Name AlwaysInstallElevated' -EvidenceData ($AlwaysInstallElevated)
}

# ============================================================================
# AUTOLOGON
# ============================================================================

Write-Host "[+] AutoLogon"

$WinlogonPath = `
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$AutoLogon = [PSCustomObject]@{

    AutoAdminLogon =
        Get-RegistryValue $WinlogonPath "AutoAdminLogon"

    DefaultUserName =
        Get-RegistryValue $WinlogonPath "DefaultUserName"

    DefaultDomainName =
        Get-RegistryValue $WinlogonPath "DefaultDomainName"

    DefaultPasswordConfigured =
        Test-RegistryValueExists `
            $WinlogonPath `
            "DefaultPassword"
}

#
# Deliberately do NOT retrieve DefaultPassword.
#

if ($AutoLogon.AutoAdminLogon -eq "1") {

    Add-Finding `
        "High" `
        "Credential Protection" `
        "Automatic administrative logon is configured" `
        "Fail" `
        "AutoAdminLogon=1; User=$($AutoLogon.DefaultUserName); PasswordValuePresent=$($AutoLogon.DefaultPasswordConfigured)" `
        "Disable AutoAdminLogon and use an appropriate managed service or automated sign-in mechanism if required." `
        -Command 'Get-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'' -Name AutoAdminLogon,DefaultUserName,DefaultDomainName
(Get-Item -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'').GetValueNames() -contains ''DefaultPassword''' -EvidenceData ($AutoLogon)
}

# ============================================================================
# DEFENDER
# ============================================================================

Write-Host "[+] Microsoft Defender / ASR"

$DefenderStatus = Invoke-SafeCommand "DefenderStatus" {

    Get-MpComputerStatus |
    Select-Object `
        AMServiceEnabled,
        AntivirusEnabled,
        AntispywareEnabled,
        BehaviorMonitorEnabled,
        IoavProtectionEnabled,
        NISEnabled,
        OnAccessProtectionEnabled,
        RealTimeProtectionEnabled,
        IsTamperProtected,
        AntivirusSignatureVersion,
        AntivirusSignatureLastUpdated,
        DefenderSignaturesOutOfDate,
        QuickScanAge,
        FullScanAge
}

$DefenderPreferences = Invoke-SafeCommand "DefenderPreferences" {

    Get-MpPreference |
    Select-Object `
        DisableRealtimeMonitoring,
        DisableBehaviorMonitoring,
        DisableIOAVProtection,
        DisableScriptScanning,
        DisableArchiveScanning,
        DisableEmailScanning,
        MAPSReporting,
        SubmitSamplesConsent,
        PUAProtection,
        EnableNetworkProtection,
        CloudBlockLevel,
        AttackSurfaceReductionRules_Ids,
        AttackSurfaceReductionRules_Actions,
        AttackSurfaceReductionOnlyExclusions,
        ControlledFolderAccessProtectedFolders,
        EnableControlledFolderAccess,
        ExclusionPath,
        ExclusionProcess,
        ExclusionExtension,
        ExclusionIpAddress
}

$ASRRules = @()

if ($DefenderPreferences) {

    $Ids     = @($DefenderPreferences.AttackSurfaceReductionRules_Ids)
    $Actions = @($DefenderPreferences.AttackSurfaceReductionRules_Actions)

    for (
        $i = 0;
        $i -lt $Ids.Count;
        $i++
    ) {

        $Action = $null

        if ($i -lt $Actions.Count) {
            $Action = $Actions[$i]
        }

        $ASRRules += [PSCustomObject]@{
            RuleId = $Ids[$i]
            Action = $Action
        }
    }
}

if (
    $DefenderStatus -and
    $DefenderStatus.RealTimeProtectionEnabled -eq $false
) {

    Add-Finding `
        "High" `
        "Endpoint Protection" `
        "Microsoft Defender real-time protection is disabled" `
        "Fail" `
        "RealTimeProtectionEnabled=False" `
        "Enable Defender real-time protection or verify an approved third-party endpoint protection platform provides equivalent protection." `
        -Command 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled' -EvidenceData ($DefenderStatus)
}

if (
    $DefenderPreferences -and
    $DefenderPreferences.DisableScriptScanning -eq $true
) {

    Add-Finding `
        "Medium" `
        "Endpoint Protection" `
        "Defender script scanning is disabled" `
        "Fail" `
        "DisableScriptScanning=True" `
        "Enable Microsoft Defender script scanning unless explicitly excluded through approved policy." `
        -Command 'Get-MpPreference | Select-Object DisableScriptScanning' -EvidenceData ($DefenderPreferences)
}

if (
    $DefenderPreferences -and
    $DefenderPreferences.PUAProtection -eq 0
) {

    Add-Finding `
        "Low" `
        "Endpoint Protection" `
        "Potentially unwanted application protection is disabled" `
        "Review" `
        "PUAProtection=0" `
        "Consider enabling PUA protection." `
        -Command 'Get-MpPreference | Select-Object PUAProtection' -EvidenceData ($DefenderPreferences)
}

$DefenderExclusions = @()

if ($DefenderPreferences) {

    foreach ($Item in @($DefenderPreferences.ExclusionPath)) {

        if ($Item) {
            $DefenderExclusions += [PSCustomObject]@{
                Type  = "Path"
                Value = $Item
            }
        }
    }

    foreach ($Item in @($DefenderPreferences.ExclusionProcess)) {

        if ($Item) {
            $DefenderExclusions += [PSCustomObject]@{
                Type  = "Process"
                Value = $Item
            }
        }
    }

    foreach ($Item in @($DefenderPreferences.ExclusionExtension)) {

        if ($Item) {
            $DefenderExclusions += [PSCustomObject]@{
                Type  = "Extension"
                Value = $Item
            }
        }
    }
}

if (@($DefenderExclusions).Count -gt 0) {

    Add-Finding `
        "Informational" `
        "Endpoint Protection" `
        "Microsoft Defender exclusions are configured" `
        "Review" `
        (Convert-ToSafeString $DefenderExclusions) `
        "Review each exclusion for necessity, scope, and approval." `
        -Command 'Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension | Format-List' -EvidenceData ($DefenderExclusions)
}

# ============================================================================
# FIREWALL
# ============================================================================

Write-Host "[+] Windows Firewall"

$FirewallProfiles = Invoke-SafeCommand "FirewallProfiles" {

    Get-NetFirewallProfile |
    Select-Object `
        Name,
        Enabled,
        DefaultInboundAction,
        DefaultOutboundAction,
        NotifyOnListen,
        LogFileName,
        LogAllowed,
        LogBlocked,
        LogMaxSizeKilobytes
}

foreach ($Profile in @($FirewallProfiles)) {

    if ($Profile.Enabled -eq $false) {

        Add-Finding `
            "High" `
            "Network Security" `
            "Windows Firewall profile disabled: $($Profile.Name)" `
            "Fail" `
            "Profile=$($Profile.Name); Enabled=False" `
            "Enable Windows Defender Firewall for applicable profiles." `
        -Command "Get-NetFirewallProfile -Name $(ConvertTo-PowerShellLiteral $Profile.Name) | Select-Object Name,Enabled" -EvidenceData ($Profile)
    }

    if ($Profile.LogBlocked -eq $false) {

        Add-Finding `
            "Low" `
            "Logging" `
            "Dropped firewall packets are not logged for $($Profile.Name)" `
            "Review" `
            "LogBlocked=False" `
            "Consider enabling firewall drop logging where appropriate." `
        -Command "Get-NetFirewallProfile -Name $(ConvertTo-PowerShellLiteral $Profile.Name) | Select-Object Name,LogBlocked" -EvidenceData ($Profile)
    }
}

$EnabledInboundFirewallRules = @()
$BroadInboundFirewallRules   = @()

$FirewallRuleObjects = Invoke-SafeCommand "FirewallRules" {

    Get-NetFirewallRule |
    Where-Object {
        $_.Enabled -eq "True" -and
        $_.Direction -eq "Inbound" -and
        $_.Action -eq "Allow"
    }
}

foreach ($Rule in @($FirewallRuleObjects)) {

    $Ports = $Rule |
        Get-NetFirewallPortFilter

    $Addresses = $Rule |
        Get-NetFirewallAddressFilter

    $Applications = $Rule |
        Get-NetFirewallApplicationFilter

    $Entry = [PSCustomObject]@{

        DisplayName = $Rule.DisplayName
        Profile     = $Rule.Profile
        Program     = $Applications.Program
        Protocol    = $Ports.Protocol
        LocalPort   = $Ports.LocalPort
        RemotePort  = $Ports.RemotePort
        RemoteAddress = $Addresses.RemoteAddress
    }

    $EnabledInboundFirewallRules += $Entry

    $RemoteAddressText = "$($Addresses.RemoteAddress)"

    if (
        $RemoteAddressText -match "Any" -or
        $RemoteAddressText -eq "*"
    ) {

        if (
            "$($Ports.LocalPort)" -eq "Any" -or
            "$($Ports.LocalPort)" -eq "*"
        ) {

            $BroadInboundFirewallRules += $Entry
        }
    }
}

if (@($BroadInboundFirewallRules).Count -gt 0) {

    Add-Finding `
        "Medium" `
        "Network Security" `
        "Broad inbound firewall allow rules detected" `
        "Review" `
        (Convert-ToSafeString $BroadInboundFirewallRules) `
        "Restrict inbound rules by source address, destination port, application, and profile where operationally feasible." `
        -Command 'Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
    $rule = $_
    $port = $rule | Get-NetFirewallPortFilter
    $address = $rule | Get-NetFirewallAddressFilter
    $app = $rule | Get-NetFirewallApplicationFilter
    [pscustomobject]@{Name=$rule.DisplayName; Profile=$rule.Profile; LocalPort=$port.LocalPort; RemoteAddress=$address.RemoteAddress; Program=$app.Program}
} | Format-List' -EvidenceData ($BroadInboundFirewallRules)
}

# ============================================================================
# NETWORK
# ============================================================================

Write-Host "[+] Network configuration"

$NetworkAdapters = Invoke-SafeCommand "NetworkAdapters" {

    Get-NetAdapter |
    Select-Object `
        Name,
        InterfaceDescription,
        Status,
        MacAddress,
        LinkSpeed
}

$IPConfiguration = Invoke-SafeCommand "IPConfiguration" {

    Get-NetIPConfiguration |
    Select-Object `
        InterfaceAlias,
        InterfaceDescription,
        IPv4Address,
        IPv6Address,
        IPv4DefaultGateway,
        DNSServer
}

$Routes = Invoke-SafeCommand "Routes" {

    Get-NetRoute |
    Where-Object AddressFamily -eq IPv4 |
    Select-Object `
        DestinationPrefix,
        NextHop,
        RouteMetric,
        InterfaceAlias
}

$ListeningTCP = Invoke-SafeCommand "TCPListeners" {

    Get-NetTCPConnection `
        -State Listen |
    Sort-Object LocalPort |
    Select-Object `
        LocalAddress,
        LocalPort,
        OwningProcess,
        @{
            Name = "ProcessName"

            Expression = {

                try {
                    (
                        Get-Process `
                            -Id $_.OwningProcess `
                            -ErrorAction Stop
                    ).ProcessName
                }
                catch {
                    "Unknown"
                }
            }
        }
}

$ListeningUDP = Invoke-SafeCommand "UDPListeners" {

    Get-NetUDPEndpoint |
    Sort-Object LocalPort |
    Select-Object `
        LocalAddress,
        LocalPort,
        OwningProcess,
        @{
            Name = "ProcessName"

            Expression = {

                try {
                    (
                        Get-Process `
                            -Id $_.OwningProcess `
                            -ErrorAction Stop
                    ).ProcessName
                }
                catch {
                    "Unknown"
                }
            }
        }
}

# ============================================================================
# SMB
# ============================================================================

Write-Host "[+] SMB"

$SMBServer = Invoke-SafeCommand "SMBServer" {

    Get-SmbServerConfiguration |
    Select-Object `
        EnableSMB1Protocol,
        EnableSMB2Protocol,
        EnableSecuritySignature,
        RequireSecuritySignature,
        EncryptData,
        RejectUnencryptedAccess,
        EnableMultiChannel
}

$SMBClient = Invoke-SafeCommand "SMBClient" {

    Get-SmbClientConfiguration |
    Select-Object `
        EnableSecuritySignature,
        RequireSecuritySignature,
        EnableInsecureGuestLogons
}

$Shares = Invoke-SafeCommand "SMBShares" {

    Get-SmbShare |
    Select-Object `
        Name,
        Path,
        Description,
        EncryptData,
        FolderEnumerationMode,
        Special
}

$ShareAccess = @()

foreach ($Share in @($Shares)) {

    try {

        $Access = Get-SmbShareAccess `
            -Name $Share.Name

        foreach ($Ace in $Access) {

            $ShareAccess += [PSCustomObject]@{

                Share       = $Share.Name
                AccountName = $Ace.AccountName
                AccessRight = $Ace.AccessRight
                AccessType  = $Ace.AccessControlType
            }
        }
    }
    catch {}
}

if (
    $SMBServer -and
    $SMBServer.EnableSMB1Protocol -eq $true
) {

    Add-Finding `
        "High" `
        "SMB" `
        "SMBv1 is enabled" `
        "Fail" `
        "EnableSMB1Protocol=True" `
        "Disable SMBv1 unless there is an approved legacy dependency." `
        -Command 'Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol' -EvidenceData ($SMBServer)
}

if (
    $SMBServer -and
    $SMBServer.RequireSecuritySignature -eq $false
) {

    Add-Finding `
        "Medium" `
        "SMB" `
        "SMB server signing is not required" `
        "Review" `
        "RequireSecuritySignature=False" `
        "Consider requiring SMB signing after compatibility validation." `
        -Command 'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature' -EvidenceData ($SMBServer)
}

if (
    $SMBClient -and
    $SMBClient.RequireSecuritySignature -eq $false
) {

    Add-Finding `
        "Low" `
        "SMB" `
        "SMB client signing is not required" `
        "Review" `
        "RequireSecuritySignature=False" `
        "Review whether SMB client signing should be required under the organisation's baseline." `
        -Command 'Get-SmbClientConfiguration | Select-Object RequireSecuritySignature' -EvidenceData ($SMBClient)
}

if (
    $SMBClient -and
    $SMBClient.EnableInsecureGuestLogons -eq $true
) {

    Add-Finding `
        "High" `
        "SMB" `
        "Insecure SMB guest logons are enabled" `
        "Fail" `
        "EnableInsecureGuestLogons=True" `
        "Disable insecure SMB guest logons." `
        -Command 'Get-SmbClientConfiguration | Select-Object EnableInsecureGuestLogons' -EvidenceData ($SMBClient)
}

foreach ($Ace in @($ShareAccess)) {

    if (
        $Ace.AccessType -eq "Allow" -and
        (
            $Ace.AccountName -match "Everyone" -or
            $Ace.AccountName -match "Authenticated Users"
        ) -and
        (
            $Ace.AccessRight -eq "Full" -or
            $Ace.AccessRight -eq "Change"
        )
    ) {

        Add-Finding `
            "Medium" `
            "SMB" `
            "Broad write access to SMB share: $($Ace.Share)" `
            "Review" `
            "$($Ace.AccountName): $($Ace.AccessRight)" `
            "Restrict writable SMB share permissions to required users and groups." `
        -Command "Get-SmbShareAccess -Name $(ConvertTo-PowerShellLiteral $Ace.Share)" -EvidenceData ($Ace)
    }
}

# ============================================================================
# NTLM / ANONYMOUS ACCESS
# ============================================================================

Write-Host "[+] NTLM / anonymous access"

$LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

$NTLMSecurity = [PSCustomObject]@{

    LmCompatibilityLevel =
        Get-RegistryValue $LsaPath "LmCompatibilityLevel"

    RestrictAnonymous =
        Get-RegistryValue $LsaPath "RestrictAnonymous"

    RestrictAnonymousSAM =
        Get-RegistryValue $LsaPath "RestrictAnonymousSAM"

    EveryoneIncludesAnonymous =
        Get-RegistryValue $LsaPath "EveryoneIncludesAnonymous"

    NoLMHash =
        Get-RegistryValue $LsaPath "NoLMHash"

    RestrictSendingNTLMTraffic =
        Get-RegistryValue `
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            "RestrictSendingNTLMTraffic"

    RestrictReceivingNTLMTraffic =
        Get-RegistryValue `
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            "RestrictReceivingNTLMTraffic"
}

if (
    $null -ne $NTLMSecurity.LmCompatibilityLevel -and
    [int]$NTLMSecurity.LmCompatibilityLevel -lt 5
) {

    Add-Finding `
        "Medium" `
        "Authentication" `
        "NTLM compatibility level permits legacy authentication" `
        "Review" `
        "LmCompatibilityLevel=$($NTLMSecurity.LmCompatibilityLevel)" `
        "Review NTLM policy and migrate toward NTLMv2-only or stronger authentication according to application compatibility." `
        -Command (Get-RegistryReviewCommand $LsaPath @('LmCompatibilityLevel')) -EvidenceData ($NTLMSecurity)
}

if ($NTLMSecurity.EveryoneIncludesAnonymous -eq 1) {

    Add-Finding `
        "High" `
        "Authentication" `
        "Anonymous users are included in Everyone permissions" `
        "Fail" `
        "EveryoneIncludesAnonymous=1" `
        "Disable EveryoneIncludesAnonymous unless explicitly required." `
        -Command (Get-RegistryReviewCommand $LsaPath @('EveryoneIncludesAnonymous')) -EvidenceData ($NTLMSecurity)
}

# ============================================================================
# RDP
# ============================================================================

Write-Host "[+] RDP"

$RdpBase = `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"

$RdpTcp = `
    "$RdpBase\WinStations\RDP-Tcp"

$RDPConfig = [PSCustomObject]@{

    Enabled =
        (
            Get-RegistryValue `
                $RdpBase `
                "fDenyTSConnections"
        ) -eq 0

    NLAEnabled =
        (
            Get-RegistryValue `
                $RdpTcp `
                "UserAuthentication"
        ) -eq 1

    SecurityLayer =
        Get-RegistryValue `
            $RdpTcp `
            "SecurityLayer"

    MinEncryptionLevel =
        Get-RegistryValue `
            $RdpTcp `
            "MinEncryptionLevel"

    PortNumber =
        Get-RegistryValue `
            $RdpTcp `
            "PortNumber"

    RestrictedAdminDisable =
        Get-RegistryValue `
            $LsaPath `
            "DisableRestrictedAdmin"
}

if (
    $RDPConfig.Enabled -and
    -not $RDPConfig.NLAEnabled
) {

    Add-Finding `
        "High" `
        "Remote Access" `
        "RDP is enabled without Network Level Authentication" `
        "Fail" `
        "RDP=True; NLA=False" `
        "Require Network Level Authentication for RDP." `
        -Command (Get-RegistryReviewCommand $RdpTcp @('UserAuthentication')) -EvidenceData ($RDPConfig)
}

if ($RDPConfig.Enabled) {

    Add-Finding `
        "Informational" `
        "Remote Access" `
        "Remote Desktop is enabled" `
        "Review" `
        "Port=$($RDPConfig.PortNumber)" `
        "Confirm RDP is required and restrict source networks through firewall controls." `
        -Command ((Get-RegistryReviewCommand $RdpBase @('fDenyTSConnections')) + [Environment]::NewLine + (Get-RegistryReviewCommand $RdpTcp @('PortNumber'))) -EvidenceData ($RDPConfig)
}

# ============================================================================
# WINRM
# ============================================================================

Write-Host "[+] WinRM"

$WinRMService = Invoke-SafeCommand "WinRMService" {

    Get-Service WinRM |
    Select-Object `
        Name,
        Status,
        StartType
}

$TrustedHosts = Invoke-SafeCommand "WinRMTrustedHosts" {

    (
        Get-Item `
            WSMan:\localhost\Client\TrustedHosts
    ).Value
}

$WinRMConfig = Invoke-SafeCommand "WinRMConfig" {

    winrm.exe get winrm/config 2>&1
}

if (
    $TrustedHosts -eq "*" -or
    "$TrustedHosts" -match "^\*$"
) {

    Add-Finding `
        "Medium" `
        "Remote Access" `
        "WinRM TrustedHosts permits all hosts" `
        "Review" `
        "TrustedHosts=*" `
        "Restrict WinRM TrustedHosts to approved management endpoints." `
        -Command '(Get-Item WSMan:\localhost\Client\TrustedHosts).Value' -EvidenceData ($TrustedHosts)
}

# ============================================================================
# POWERSHELL SECURITY
# ============================================================================

Write-Host "[+] PowerShell logging"

$PowerShellSecurity = [PSCustomObject]@{

    Version =
        $PSVersionTable.PSVersion.ToString()

    Edition =
        $PSVersionTable.PSEdition

    LanguageMode =
        "$($ExecutionContext.SessionState.LanguageMode)"

    ExecutionPolicy =
        Get-ExecutionPolicy

    ScriptBlockLogging =
        Get-RegistryValue `
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
            "EnableScriptBlockLogging"

    InvocationLogging =
        Get-RegistryValue `
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
            "EnableScriptBlockInvocationLogging"

    ModuleLogging =
        Get-RegistryValue `
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
            "EnableModuleLogging"

    Transcription =
        Get-RegistryValue `
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
            "EnableTranscripting"

    ProtectedEventLogging =
        Get-RegistryValue `
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging" `
            "EnableProtectedEventLogging"
}

if ($PowerShellSecurity.ScriptBlockLogging -ne 1) {

    Add-Finding `
        "Low" `
        "Logging" `
        "PowerShell Script Block Logging is not explicitly enabled" `
        "Review" `
        "EnableScriptBlockLogging=$($PowerShellSecurity.ScriptBlockLogging)" `
        "Consider enabling PowerShell Script Block Logging on administrative servers." `
        -Command (Get-RegistryReviewCommand 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' @('EnableScriptBlockLogging')) -EvidenceData ($PowerShellSecurity)
}

if ($PowerShellSecurity.ModuleLogging -ne 1) {

    Add-Finding `
        "Low" `
        "Logging" `
        "PowerShell Module Logging is not explicitly enabled" `
        "Review" `
        "EnableModuleLogging=$($PowerShellSecurity.ModuleLogging)" `
        "Consider enabling module logging for security monitoring." `
        -Command (Get-RegistryReviewCommand 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' @('EnableModuleLogging')) -EvidenceData ($PowerShellSecurity)
}

# ============================================================================
# CREDENTIAL PROTECTION
# ============================================================================

Write-Host "[+] LSA / Credential Guard"

$CredentialSecurity = [PSCustomObject]@{

    RunAsPPL =
        Get-RegistryValue `
            $LsaPath `
            "RunAsPPL"

    NoLMHash =
        Get-RegistryValue `
            $LsaPath `
            "NoLMHash"

    CachedLogonsCount =
        Get-RegistryValue `
            $WinlogonPath `
            "CachedLogonsCount"

    WDigestUseLogonCredential =
        Get-RegistryValue `
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
            "UseLogonCredential"

    DisableRestrictedAdmin =
        Get-RegistryValue `
            $LsaPath `
            "DisableRestrictedAdmin"
}

if ($CredentialSecurity.WDigestUseLogonCredential -eq 1) {

    Add-Finding `
        "High" `
        "Credential Protection" `
        "WDigest credential caching is explicitly enabled" `
        "Fail" `
        "UseLogonCredential=1" `
        "Disable WDigest credential caching." `
        -Command (Get-RegistryReviewCommand 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' @('UseLogonCredential')) -EvidenceData ($CredentialSecurity)
}

if (
    $CredentialSecurity.RunAsPPL -ne 1 -and
    $CredentialSecurity.RunAsPPL -ne 2
) {

    Add-Finding `
        "Medium" `
        "Credential Protection" `
        "LSA protection is not explicitly configured" `
        "Review" `
        "RunAsPPL=$($CredentialSecurity.RunAsPPL)" `
        "Evaluate enabling LSA protection after application compatibility testing." `
        -Command (Get-RegistryReviewCommand $LsaPath @('RunAsPPL')) -EvidenceData ($CredentialSecurity)
}

$DeviceGuard = Invoke-SafeCommand "DeviceGuard" {

    Get-CimInstance `
        -Namespace `
            root\Microsoft\Windows\DeviceGuard `
        -ClassName `
            Win32_DeviceGuard |
    Select-Object `
        VirtualizationBasedSecurityStatus,
        SecurityServicesConfigured,
        SecurityServicesRunning,
        CodeIntegrityPolicyEnforcementStatus,
        UsermodeCodeIntegrityPolicyEnforcementStatus,
        AvailableSecurityProperties,
        RequiredSecurityProperties
}

# ============================================================================
# APPLOCKER
# ============================================================================

Write-Host "[+] AppLocker"

$AppLockerService = Invoke-SafeCommand "AppLockerService" {

    Get-Service AppIDSvc |
    Select-Object `
        Name,
        Status,
        StartType
}

$AppLockerCollections = @()
$AppLockerRules       = @()
$AppLockerXML         = $null

try {

    if (
        Get-Command `
            Get-AppLockerPolicy `
            -ErrorAction SilentlyContinue
    ) {

        $AppLockerXML = Get-AppLockerPolicy `
            -Effective `
            -Xml

        if ($AppLockerXML) {

            [xml]$AppLockerDocument = $AppLockerXML

            foreach (
                $Collection in
                $AppLockerDocument.AppLockerPolicy.RuleCollection
            ) {

                $Rules = @()

                foreach ($Child in $Collection.ChildNodes) {

                    if ($Child.NodeType -ne "Element") {
                        continue
                    }

                    $Rules += $Child

                    $AppLockerRules += [PSCustomObject]@{

                        CollectionType =
                            $Collection.Type

                        EnforcementMode =
                            $Collection.EnforcementMode

                        RuleType =
                            $Child.Name

                        RuleName =
                            $Child.Name

                        RuleId =
                            $Child.Id

                        UserOrGroupSid =
                            $Child.UserOrGroupSid

                        Action =
                            $Child.Action
                    }
                }

                $AppLockerCollections += [PSCustomObject]@{

                    CollectionType =
                        $Collection.Type

                    EnforcementMode =
                        $Collection.EnforcementMode

                    RuleCount =
                        @($Rules).Count
                }
            }
        }
    }
}
catch {

    Add-CollectionError `
        "AppLocker" `
        $_.Exception.Message
}

$EnforcedCollections = @(
    $AppLockerCollections |
    Where-Object {
        $_.EnforcementMode -eq "Enabled"
    }
)

if (@($EnforcedCollections).Count -eq 0) {

    Add-Finding `
        "Low" `
        "Application Control" `
        "No enforced AppLocker rule collections detected" `
        "Review" `
        "Effective enforced collections=0" `
        "Determine whether AppLocker or WDAC application control is required by the server security baseline." `
        -Command 'Get-AppLockerPolicy -Effective -Xml' -EvidenceData ($AppLockerCollections)
}

# ============================================================================
# WDAC / CODE INTEGRITY
# ============================================================================

Write-Host "[+] WDAC / Code Integrity"

$WDACPolicyPaths = @(
    "$env:SystemRoot\System32\CodeIntegrity\SIPolicy.p7b",
    "$env:SystemRoot\System32\CodeIntegrity\CiPolicies\Active"
)

$WDACFiles = @()

foreach ($Path in $WDACPolicyPaths) {

    if (Test-Path $Path) {

        if ((Get-Item $Path).PSIsContainer) {

            $WDACFiles += Get-ChildItem `
                $Path `
                -File `
                -ErrorAction SilentlyContinue |
            Select-Object `
                FullName,
                Length,
                LastWriteTime
        }
        else {

            $WDACFiles += Get-Item $Path |
                Select-Object `
                    FullName,
                    Length,
                    LastWriteTime
        }
    }
}

$WDAC = [PSCustomObject]@{

    PolicyFiles = $WDACFiles

    CodeIntegrityPolicyEnforcementStatus =
        $DeviceGuard.CodeIntegrityPolicyEnforcementStatus

    UserModePolicyEnforcementStatus =
        $DeviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus
}

# ============================================================================
# SERVICES
# ============================================================================

Write-Host "[+] Services / service permissions"

$Services = Invoke-SafeCommand "Services" {

    Get-CimInstance Win32_Service |
    Select-Object `
        Name,
        DisplayName,
        State,
        StartMode,
        StartName,
        PathName
}

$ServiceSecurity = @()

foreach ($Service in @($Services)) {

    $Executable = Get-ExecutableFromCommandLine `
        $Service.PathName

    $Directory = $null

    if (
        $Executable -and
        (Test-Path -LiteralPath $Executable)
    ) {

        try {

            $Directory = Split-Path `
                $Executable `
                -Parent
        }
        catch {}
    }

    $Unquoted = Test-UnquotedExecutablePath `
        $Service.PathName

    $BinaryWeakAcl = @()

    if ($Executable) {

        $BinaryWeakAcl = Get-WeakAclEntries `
            $Executable
    }

    $DirectoryWeakAcl = @()

    if ($Directory) {

        $DirectoryWeakAcl = Get-WeakAclEntries `
            $Directory
    }

    $RegistryPath = `
        "HKLM:\SYSTEM\CurrentControlSet\Services\$($Service.Name)"

    $RegistryWeakAcl = Get-WeakRegistryAclEntries `
        $RegistryPath

    $Sddl = Get-ServiceSddl `
        $Service.Name

    $WeakSddl = Test-ServiceSddlWeak `
        $Sddl

    $Entry = [PSCustomObject]@{

        Name          = $Service.Name
        DisplayName   = $Service.DisplayName
        StartMode     = $Service.StartMode
        StartName     = $Service.StartName
        PathName      = $Service.PathName
        Executable    = $Executable
        Directory     = $Directory
        UnquotedPath  = $Unquoted
        WeakBinaryAcl = $BinaryWeakAcl
        WeakDirectoryAcl = $DirectoryWeakAcl
        WeakRegistryAcl  = $RegistryWeakAcl
        ServiceSDDL      = $Sddl
        BroadServiceControlRights = $WeakSddl
    }

    $ServiceSecurity += $Entry

    if ($Unquoted) {

        Add-Finding `
            "Medium" `
            "Privilege Escalation" `
            "Unquoted service executable path: $($Service.Name)" `
            "Review" `
            "$($Service.PathName)" `
            "Quote the service executable path and review the permissions of each parent directory." `
        -Command "Get-CimInstance Win32_Service | Where-Object Name -eq $(ConvertTo-PowerShellLiteral $Service.Name) | Select-Object Name,PathName,StartName,StartMode" -EvidenceData ($Entry)
    }

    if (@($BinaryWeakAcl).Count -gt 0) {

        Add-Finding `
            "High" `
            "Privilege Escalation" `
            "Service executable is writable by a broad principal: $($Service.Name)" `
            "Fail" `
            (Convert-ToSafeString $BinaryWeakAcl) `
            "Remove unnecessary write permissions from the service executable." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $Executable)).Access | Format-Table -Wrap" -EvidenceData ($Entry)
    }

    if (@($DirectoryWeakAcl).Count -gt 0) {

        Add-Finding `
            "High" `
            "Privilege Escalation" `
            "Service executable directory is writable by a broad principal: $($Service.Name)" `
            "Fail" `
            (Convert-ToSafeString $DirectoryWeakAcl) `
            "Restrict write access to the service program directory." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $Directory)).Access | Format-Table -Wrap" -EvidenceData ($Entry)
    }

    if (@($RegistryWeakAcl).Count -gt 0) {

        Add-Finding `
            "High" `
            "Privilege Escalation" `
            "Service registry configuration is writable by a broad principal: $($Service.Name)" `
            "Fail" `
            (Convert-ToSafeString $RegistryWeakAcl) `
            "Restrict modification rights on the service registry configuration." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $RegistryPath)).Access | Format-Table -Wrap" -EvidenceData ($Entry)
    }

    if ($WeakSddl) {

        Add-Finding `
            "Medium" `
            "Privilege Escalation" `
            "Potentially broad service-object permissions: $($Service.Name)" `
            "Review" `
            "$Sddl" `
            "Review the service security descriptor and remove unnecessary modification/control rights from non-administrative principals." `
        -Command "sc.exe sdshow $(ConvertTo-PowerShellLiteral $Service.Name)" -EvidenceData ($Entry)
    }
}

# ============================================================================
# SCHEDULED TASKS
# ============================================================================

Write-Host "[+] Scheduled task security"

$ScheduledTaskSecurity = @()

$Tasks = Invoke-SafeCommand "ScheduledTasks" {

    Get-ScheduledTask
}

foreach ($Task in @($Tasks)) {

    $TaskFileRelative = (
        "$($Task.TaskPath)$($Task.TaskName)"
    ).TrimStart("\")

    $TaskFile = Join-Path `
        "$env:SystemRoot\System32\Tasks" `
        $TaskFileRelative

    $TaskFileWeakAcl = Get-WeakAclEntries `
        $TaskFile

    $TaskFileFindingReported = $false
    foreach ($Action in @($Task.Actions)) {

        $ActionExecutable = $Action.Execute

        if ($ActionExecutable) {

            $ActionExecutable = `
                [Environment]::ExpandEnvironmentVariables(
                    $ActionExecutable
                )
        }

        $ActionWeakAcl = @()
        $ActionDirectoryWeakAcl = @()

        if (
            $ActionExecutable -and
            (Test-Path -LiteralPath $ActionExecutable)
        ) {

            $ActionWeakAcl = Get-WeakAclEntries `
                $ActionExecutable

            $Parent = Split-Path `
                $ActionExecutable `
                -Parent

            $ActionDirectoryWeakAcl = Get-WeakAclEntries `
                $Parent
        }

        $Entry = [PSCustomObject]@{

            TaskName       = $Task.TaskName
            TaskPath       = $Task.TaskPath
            State          = $Task.State
            RunAs          = $Task.Principal.UserId
            GroupId        = $Task.Principal.GroupId
            LogonType      = [string]$Task.Principal.LogonType
            RunLevel       = $Task.Principal.RunLevel
            Enabled        = $Task.Settings.Enabled
            AllowDemandStart = $Task.Settings.AllowDemandStart
            Actions        = @($Task.Actions | Select-Object Execute,Arguments,WorkingDirectory,ClassId,Data)
            Triggers       = @($Task.Triggers | Select-Object @{Name='Type';Expression={$_.CimClass.CimClassName}},Enabled,StartBoundary,EndBoundary)
            TaskFile       = $TaskFile
            TaskFileWeakAcl = $TaskFileWeakAcl
            Action         = $ActionExecutable
            Arguments      = $Action.Arguments
            ActionWeakAcl  = $ActionWeakAcl
            ActionDirectoryWeakAcl = $ActionDirectoryWeakAcl
        }

        $ScheduledTaskSecurity += $Entry

        if (@($TaskFileWeakAcl).Count -gt 0 -and -not $TaskFileFindingReported) {

            $TaskFileFindingReported = $true

            Add-Finding `
                "High" `
                "Privilege Escalation" `
                "Scheduled task definition is broadly writable: $($Task.TaskName)" `
                "Review" `
                (Convert-ToSafeString $TaskFileWeakAcl) `
                "Restrict write access to the scheduled task definition." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $TaskFile)).Access | Format-Table -Wrap" -EvidenceData ($Entry)
        }

        if (@($ActionWeakAcl).Count -gt 0) {

            Add-Finding `
                "High" `
                "Privilege Escalation" `
                "Scheduled task executable is broadly writable: $($Task.TaskName)" `
                "Fail" `
                (Convert-ToSafeString $ActionWeakAcl) `
                "Restrict write permissions on the scheduled task executable." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $ActionExecutable)).Access | Format-Table -Wrap" -EvidenceData ($Entry)
        }

        if (@($ActionDirectoryWeakAcl).Count -gt 0) {

            Add-Finding `
                "High" `
                "Privilege Escalation" `
                "Scheduled task executable directory is broadly writable: $($Task.TaskName)" `
                "Fail" `
                (Convert-ToSafeString $ActionDirectoryWeakAcl) `
                "Restrict write permissions on the scheduled task program directory." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $Parent)).Access | Format-Table -Wrap" -EvidenceData ($Entry)
        }
    }
}

# ============================================================================
# AUTORUNS
# ============================================================================

Write-Host "[+] Autorun locations"

$AutorunLocations = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$Autoruns = @()

foreach ($RegistryPath in $AutorunLocations) {

    if (-not (Test-Path $RegistryPath)) {
        continue
    }

    $RegistryWeakAcl = Get-WeakRegistryAclEntries `
        $RegistryPath

    try {

        $Properties = (
            Get-ItemProperty $RegistryPath
        ).PSObject.Properties |
        Where-Object {
            $_.Name -notmatch "^PS"
        }

        foreach ($Property in $Properties) {

            $Executable = Get-ExecutableFromCommandLine `
                "$($Property.Value)"

            $BinaryWeakAcl = @()
            $DirectoryWeakAcl = @()

            if (
                $Executable -and
                (Test-Path -LiteralPath $Executable)
            ) {

                $BinaryWeakAcl = Get-WeakAclEntries `
                    $Executable

                $Parent = Split-Path `
                    $Executable `
                    -Parent

                $DirectoryWeakAcl = Get-WeakAclEntries `
                    $Parent
            }

            $Autoruns += [PSCustomObject]@{

                RegistryPath = $RegistryPath
                Name         = $Property.Name
                Command      = $Property.Value
                Executable   = $Executable
                RegistryWeakAcl = $RegistryWeakAcl
                BinaryWeakAcl   = $BinaryWeakAcl
                DirectoryWeakAcl = $DirectoryWeakAcl
            }

            if (@($BinaryWeakAcl).Count -gt 0) {

                Add-Finding `
                    "High" `
                    "Privilege Escalation" `
                    "Autorun executable is broadly writable: $($Property.Name)" `
                    "Fail" `
                    (Convert-ToSafeString $BinaryWeakAcl) `
                    "Restrict write access to the autorun executable." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $Executable)).Access | Format-Table -Wrap" -EvidenceData ($Autoruns[-1])
            }

            if (@($DirectoryWeakAcl).Count -gt 0) {

                Add-Finding `
                    "High" `
                    "Privilege Escalation" `
                    "Autorun executable directory is broadly writable: $($Property.Name)" `
                    "Fail" `
                    (Convert-ToSafeString $DirectoryWeakAcl) `
                    "Restrict write access to the autorun program directory." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $Parent)).Access | Format-Table -Wrap" -EvidenceData ($Autoruns[-1])
            }
        }
    }
    catch {}
}

# ============================================================================
# PATH / DLL SEARCH SECURITY
# ============================================================================

Write-Host "[+] PATH / DLL search configuration"

$MachinePath = `
    [Environment]::GetEnvironmentVariable(
        "PATH",
        "Machine"
    )

$PathSecurity = @()

foreach ($PathEntry in ($MachinePath -split ";")) {

    $PathEntry = $PathEntry.Trim()

    if ([string]::IsNullOrWhiteSpace($PathEntry)) {
        continue
    }

    $ExpandedPath = `
        [Environment]::ExpandEnvironmentVariables(
            $PathEntry
        )

    $WeakAcl = Get-WeakAclEntries `
        $ExpandedPath

    $PathSecurity += [PSCustomObject]@{

        Path    = $ExpandedPath
        Exists  = Test-Path $ExpandedPath
        WeakAcl = $WeakAcl
    }

    if (@($WeakAcl).Count -gt 0) {

        Add-Finding `
            "High" `
            "Privilege Escalation" `
            "System PATH directory is broadly writable" `
            "Fail" `
            "Path=$ExpandedPath`n$(Convert-ToSafeString $WeakAcl)" `
            "Remove unnecessary write access to directories included in the system PATH." `
        -Command "(Get-Acl -LiteralPath $(ConvertTo-PowerShellLiteral $ExpandedPath)).Access | Format-Table -Wrap" -EvidenceData ($PathSecurity[-1])
    }
}

$DLLSearchSecurity = [PSCustomObject]@{

    SafeDllSearchMode =
        Get-RegistryValue `
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
            "SafeDllSearchMode"

    CWDIllegalInDllSearch =
        Get-RegistryValue `
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" `
            "CWDIllegalInDllSearch"
}

if ($DLLSearchSecurity.SafeDllSearchMode -eq 0) {

    Add-Finding `
        "Medium" `
        "Privilege Escalation" `
        "Safe DLL search mode is disabled" `
        "Fail" `
        "SafeDllSearchMode=0" `
        "Enable SafeDllSearchMode unless an approved compatibility exception exists." `
        -Command (Get-RegistryReviewCommand 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' @('SafeDllSearchMode')) -EvidenceData ($DLLSearchSecurity)
}

# ============================================================================
# LLMNR / NETBIOS
# ============================================================================

Write-Host "[+] Legacy name resolution"

$LLMNR = Get-RegistryValue `
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    "EnableMulticast"

$NetBIOS = Invoke-SafeCommand "NetBIOS" {

    Get-CimInstance `
        Win32_NetworkAdapterConfiguration |
    Where-Object IPEnabled |
    Select-Object `
        Description,
        TcpipNetbiosOptions
}

$LegacyNameResolution = [PSCustomObject]@{

    LLMNRPolicy = $LLMNR
    NetBIOS     = $NetBIOS
}

if ($LLMNR -ne 0) {

    Add-Finding `
        "Medium" `
        "Network Security" `
        "LLMNR is not explicitly disabled" `
        "Review" `
        "EnableMulticast=$LLMNR" `
        "Disable LLMNR where it is not operationally required." `
        -Command (Get-RegistryReviewCommand 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' @('EnableMulticast')) -EvidenceData ($LegacyNameResolution)
}

foreach ($Adapter in @($NetBIOS)) {

    if ($Adapter.TcpipNetbiosOptions -ne 2) {

        Add-Finding `
            "Low" `
            "Network Security" `
            "NetBIOS over TCP/IP is not explicitly disabled" `
            "Review" `
            "$($Adapter.Description): TcpipNetbiosOptions=$($Adapter.TcpipNetbiosOptions)" `
            "Disable NetBIOS over TCP/IP where legacy name resolution is not required." `
        -Command 'Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled | Select-Object Description,TcpipNetbiosOptions' -EvidenceData ($Adapter)
    }
}

# ============================================================================
# TLS / SCHANNEL
# ============================================================================

Write-Host "[+] TLS / SCHANNEL"

$ProtocolNames = @(
    "SSL 2.0",
    "SSL 3.0",
    "TLS 1.0",
    "TLS 1.1",
    "TLS 1.2",
    "TLS 1.3"
)

$SchannelProtocols = @()

foreach ($Protocol in $ProtocolNames) {

    foreach ($Role in @("Client", "Server")) {

        $Path = `
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\$Role"

        $SchannelProtocols += [PSCustomObject]@{

            Protocol = $Protocol
            Role     = $Role

            Enabled =
                Get-RegistryValue `
                    $Path `
                    "Enabled"

            DisabledByDefault =
                Get-RegistryValue `
                    $Path `
                    "DisabledByDefault"
        }
    }
}

foreach (
    $Protocol in @(
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1"
    )
) {

    $Server = $SchannelProtocols |
        Where-Object {
            $_.Protocol -eq $Protocol -and
            $_.Role -eq "Server"
        }

    if (
        $Server -and
        $Server.Enabled -eq 1
    ) {

        Add-Finding `
            "Medium" `
            "Cryptography" `
            "$Protocol server protocol is explicitly enabled" `
            "Review" `
            "Enabled=1" `
            "Disable legacy TLS/SSL protocols unless a documented compatibility requirement exists." `
        -Command (Get-RegistryReviewCommand "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\Server" @('Enabled','DisabledByDefault')) -EvidenceData ($Server)
    }
}

# ============================================================================
# LDAP SECURITY
# ============================================================================

Write-Host "[+] LDAP security indicators"

$IsDomainController = $false

if ($ComputerSystem) {

    if (
        $ComputerSystem.DomainRole -eq 4 -or
        $ComputerSystem.DomainRole -eq 5
    ) {

        $IsDomainController = $true
    }
}

$LDAPSecurity = [PSCustomObject]@{

    IsDomainController =
        $IsDomainController

    LDAPServerIntegrity =
        Get-RegistryValue `
            "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
            "LDAPServerIntegrity"

    LDAPEnforceChannelBinding =
        Get-RegistryValue `
            "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
            "LdapEnforceChannelBinding"
}

if ($IsDomainController) {

    if (
        $null -ne $LDAPSecurity.LDAPServerIntegrity -and
        $LDAPSecurity.LDAPServerIntegrity -eq 0
    ) {

        Add-Finding `
            "High" `
            "Active Directory" `
            "LDAP server signing requirement is disabled" `
            "Fail" `
            "LDAPServerIntegrity=0" `
            "Require LDAP signing after validating client compatibility." `
        -Command (Get-RegistryReviewCommand 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' @('LDAPServerIntegrity')) -EvidenceData ($LDAPSecurity)
    }

    if (
        $LDAPSecurity.LDAPEnforceChannelBinding -eq 0
    ) {

        Add-Finding `
            "Medium" `
            "Active Directory" `
            "LDAP channel binding enforcement is disabled" `
            "Review" `
            "LdapEnforceChannelBinding=0" `
            "Review LDAP channel binding policy and enable enforcement after client compatibility validation." `
        -Command (Get-RegistryReviewCommand 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' @('LdapEnforceChannelBinding')) -EvidenceData ($LDAPSecurity)
    }
}

# ============================================================================
# AUDIT POLICY
# ============================================================================

Write-Host "[+] Advanced Audit Policy"

$AuditPolicy = Invoke-SafeCommand "AuditPolicy" {

    auditpol.exe `
        /get `
        /category:* `
        /r 2>&1
}

$AuditPolicyText = Invoke-SafeCommand "AuditPolicyText" {

    auditpol.exe `
        /get `
        /category:* 2>&1
}

# ============================================================================
# EVENT LOGS
# ============================================================================

Write-Host "[+] Event log configuration"

$LogNames = @(
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-AppLocker/EXE and DLL",
    "Microsoft-Windows-AppLocker/MSI and Script",
    "Microsoft-Windows-CodeIntegrity/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
)

$EventLogs = @()

foreach ($LogName in $LogNames) {

    try {

        $Log = Get-WinEvent `
            -ListLog $LogName `
            -ErrorAction Stop

        $EventLogs += [PSCustomObject]@{

            LogName =
                $Log.LogName

            Enabled =
                $Log.IsEnabled

            RecordCount =
                $Log.RecordCount

            FileSize =
                $Log.FileSize

            MaximumSizeInBytes =
                $Log.MaximumSizeInBytes

            LogMode =
                $Log.LogMode
        }
    }
    catch {}
}

$SecurityLog = $EventLogs |
    Where-Object LogName -eq "Security"

if (
    $SecurityLog -and
    $SecurityLog.MaximumSizeInBytes -lt 1073741824
) {

    Add-Finding `
        "Low" `
        "Logging" `
        "Security event log maximum size is below 1 GB" `
        "Review" `
        "MaximumSizeInBytes=$($SecurityLog.MaximumSizeInBytes)" `
        "Review event log retention requirements based on server activity and SIEM forwarding." `
        -Command 'Get-WinEvent -ListLog Security | Select-Object LogName,MaximumSizeInBytes,LogMode' -EvidenceData ($SecurityLog)
}

# ============================================================================
# SYSMON
# ============================================================================

Write-Host "[+] Sysmon"

$Sysmon = Invoke-SafeCommand "Sysmon" {

    Get-Service `
        Sysmon,
        Sysmon64 `
        -ErrorAction SilentlyContinue |
    Select-Object `
        Name,
        Status,
        StartType
}

if (-not $Sysmon) {

    Add-Finding `
        "Informational" `
        "Logging" `
        "Sysmon service was not detected" `
        "Review" `
        "Sysmon/Sysmon64 service not present" `
        "Determine whether enhanced endpoint telemetry is provided through Sysmon or another EDR platform." `
        -Command 'Get-Service Sysmon,Sysmon64 -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType' -EvidenceData ($Sysmon)
}

# ============================================================================
# INSTALLED SOFTWARE
# ============================================================================

Write-Host "[+] Installed software"

$InstalledSoftware = @(Get-InstalledSoftwareInventory | Sort-Object DisplayName,DisplayVersion,InventorySource)

# ============================================================================
# PATCHING
# ============================================================================

Write-Host "[+] Patch status"

$HotFixes = Invoke-SafeCommand "HotFixes" {

    Get-HotFix |
    Sort-Object InstalledOn -Descending |
    Select-Object `
        HotFixID,
        Description,
        InstalledBy,
        InstalledOn
}

$LatestHotFix = $HotFixes |
    Where-Object InstalledOn |
    Select-Object -First 1

$PatchStatus = [PSCustomObject]@{

    LatestInstalledUpdate =
        $LatestHotFix

    DaysSinceLatestUpdate =
        $null
}

if (
    $LatestHotFix -and
    $LatestHotFix.InstalledOn
) {

    $PatchStatus.DaysSinceLatestUpdate = `
        [math]::Floor(
            (
                New-TimeSpan `
                    -Start $LatestHotFix.InstalledOn `
                    -End (Get-Date)
            ).TotalDays
        )

    if ($PatchStatus.DaysSinceLatestUpdate -gt 90) {

        Add-Finding `
            "High" `
            "Patch Management" `
            "No installed Windows update detected within the last 90 days" `
            "Review" `
            "Latest=$($LatestHotFix.HotFixID); Installed=$($LatestHotFix.InstalledOn)" `
            "Review patch compliance and confirm the server receives current security updates." `
        -Command 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,InstalledOn' -EvidenceData ($HotFixes)
    }
    elseif ($PatchStatus.DaysSinceLatestUpdate -gt 45) {

        Add-Finding `
            "Medium" `
            "Patch Management" `
            "No installed Windows update detected within the last 45 days" `
            "Review" `
            "Latest=$($LatestHotFix.HotFixID); Installed=$($LatestHotFix.InstalledOn)" `
            "Review patch compliance." `
        -Command 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,InstalledOn' -EvidenceData ($HotFixes)
    }
}

$PendingReboot = Get-PendingRebootStatus

if ($PendingReboot.Pending) {

    Add-Finding `
        "Low" `
        "Patch Management" `
        "System has a pending reboot" `
        "Review" `
        "$($PendingReboot.Reasons -join ', ')" `
        "Schedule a reboot after validating operational requirements." `
        -Command 'Test-Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending''
Test-Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired''
Get-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'' -Name PendingFileRenameOperations' -EvidenceData ($PendingReboot)
}

$AvailableWindowsUpdates = @()

if (-not $SkipWindowsUpdateScan) {

    try {

        Write-Host "    Checking Windows Update Agent..."

        $UpdateSession = New-Object `
            -ComObject `
            Microsoft.Update.Session

        $UpdateSearcher = `
            $UpdateSession.CreateUpdateSearcher()

        $SearchResult = `
            $UpdateSearcher.Search(
                "IsInstalled=0 and Type='Software'"
            )

        foreach ($Update in $SearchResult.Updates) {

            $AvailableWindowsUpdates += [PSCustomObject]@{

                Title       = $Update.Title
                IsMandatory = $Update.IsMandatory
                RebootRequired = $Update.RebootRequired
            }
        }

        if (@($AvailableWindowsUpdates).Count -gt 0) {

            Add-Finding `
                "Medium" `
                "Patch Management" `
                "Windows Update Agent reports missing software updates" `
                "Review" `
                "Missing update count=$(@($AvailableWindowsUpdates).Count)" `
                "Review missing updates and apply applicable security updates through the organisation's patch-management process." `
        -Command '$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$searcher.Search("IsInstalled=0 and Type=''Software''").Updates | Select-Object Title,IsMandatory,RebootRequired' -EvidenceData ($AvailableWindowsUpdates)
        }
    }
    catch {

        Add-CollectionError `
            "WindowsUpdateScan" `
            $_.Exception.Message
    }
}

# ============================================================================
# RUNNING PROCESSES
# ============================================================================

Write-Host "[+] Running processes"

$Processes = Invoke-SafeCommand "Processes" {

    Get-Process |
    Sort-Object ProcessName |
    Select-Object `
        ProcessName,
        Id,
        Path,
        Company,
        ProductVersion
}

# ============================================================================
# ACCOUNT SECURITY FINDINGS
# ============================================================================

$Guest = $LocalUsers |
    Where-Object { $_.SID.Value -match '-501$' }

if (
    $Guest -and
    $Guest.Enabled
) {

    Add-Finding `
        "Medium" `
        "Account Security" `
        "Built-in Guest account is enabled" `
        "Fail" `
        "Guest.Enabled=True" `
        "Disable the built-in Guest account unless explicitly required." `
        -Command 'Get-LocalUser | Where-Object { $_.SID.Value -match ''-501$'' } | Select-Object Name,Enabled,SID' -EvidenceData ($Guest)
}

[int]$MinimumPasswordLength = 0

if ($PasswordPolicy.MinimumPasswordLength) {

    [int]::TryParse(
        "$($PasswordPolicy.MinimumPasswordLength)",
        [ref]$MinimumPasswordLength
    ) | Out-Null
}

if (
    $null -ne $PasswordPolicy.MinimumPasswordLength -and
    "$($PasswordPolicy.MinimumPasswordLength)" -match '^\d+$' -and
    $MinimumPasswordLength -lt 14
) {

    Add-Finding `
        "Medium" `
        "Account Security" `
        "Minimum password length is below 14 characters" `
        "Review" `
        "MinimumPasswordLength=$MinimumPasswordLength" `
        "Review password requirements against the organisation's current authentication baseline." `
        -Command '$p = Join-Path $env:TEMP (''security-review-'' + [guid]::NewGuid() + ''.inf'')
try {
    secedit.exe /export /cfg $p /quiet
    if ($LASTEXITCODE -ne 0) { throw "secedit export failed: $LASTEXITCODE" }
    Get-Content -LiteralPath $p
} finally { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p } }' -EvidenceData ($PasswordPolicy)
}

if ($PasswordPolicy.ClearTextPassword -eq "1") {

    Add-Finding `
        "High" `
        "Credential Protection" `
        "Reversible password encryption is enabled" `
        "Fail" `
        "ClearTextPassword=1" `
        "Disable reversible password encryption unless required by an explicitly approved dependency." `
        -Command '$p = Join-Path $env:TEMP (''security-review-'' + [guid]::NewGuid() + ''.inf'')
try {
    secedit.exe /export /cfg $p /quiet
    if ($LASTEXITCODE -ne 0) { throw "secedit export failed: $LASTEXITCODE" }
    Get-Content -LiteralPath $p
} finally { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p } }' -EvidenceData ($PasswordPolicy)
}

if ($PasswordPolicy.LockoutBadCount -eq "0") {

    Add-Finding `
        "Low" `
        "Account Security" `
        "Account lockout threshold is not configured" `
        "Review" `
        "LockoutBadCount=0" `
        "Review account lockout controls against the organisation's authentication policy." `
        -Command '$p = Join-Path $env:TEMP (''security-review-'' + [guid]::NewGuid() + ''.inf'')
try {
    secedit.exe /export /cfg $p /quiet
    if ($LASTEXITCODE -ne 0) { throw "secedit export failed: $LASTEXITCODE" }
    Get-Content -LiteralPath $p
} finally { if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p } }' -EvidenceData ($PasswordPolicy)
}

# ============================================================================
# ADDITIONAL LOCAL CHECKS
# ============================================================================

Write-Host "[+] Additional local host checks"
Write-Host '[+] Installed software DLL loading and process-access review'
$SoftwareDllAssessment=Get-InstalledSoftwareDllAssessment -Software $InstalledSoftware -Processes $Processes -Services $ServiceSecurity -Tasks $ScheduledTaskSecurity -MaxFilesPerSoftware $DllScanMaxFilesPerSoftware -MaxCandidatesPerSoftware $DllScanMaxCandidatesPerSoftware -TimeoutSeconds $DllScanTimeoutSeconds -Skip:$SkipSoftwareDllScan

$AdditionalChecks = @(Get-AdditionalHostChecks)
$SeverityRanks = @{ Critical=0; High=1; Medium=2; Low=3; Informational=4 }
$Findings = @($Findings | Sort-Object @{Expression={$SeverityRanks[$_.Severity]}},Category,Finding)

# ============================================================================
# FINDING SUMMARY
# ============================================================================

$SeveritySummary = [PSCustomObject]@{

    Critical =
        @(
            $Findings |
            Where-Object Severity -eq Critical
        ).Count

    High =
        @(
            $Findings |
            Where-Object Severity -eq High
        ).Count

    Medium =
        @(
            $Findings |
            Where-Object Severity -eq Medium
        ).Count

    Low =
        @(
            $Findings |
            Where-Object Severity -eq Low
        ).Count

    Informational =
        @(
            $Findings |
            Where-Object Severity -eq Informational
        ).Count

    Total =
        $Findings.Count
}

# ============================================================================
# REPORT OBJECT
# ============================================================================

$Report = [ordered]@{

    Metadata = [ordered]@{

        Tool =
            "Windows Server Comprehensive Host Security Assessment"

        Version =
            "3.1"

        Host =
            $ComputerName

        CurrentUser =
            [Security.Principal.WindowsIdentity]::GetCurrent().Name

        Elevated =
            $IsAdmin

        AssessmentStarted =
            $StartTime

        AssessmentCompleted =
            Get-Date

        PowerShell =
            $PSVersionTable.PSVersion.ToString()
    }

    SeveritySummary =
        $SeveritySummary

    Findings =
        $Findings

    CollectionErrors =
        $Errors

    AdditionalChecks =
        $AdditionalChecks

    System = [ordered]@{

        OperatingSystem =
            $OS

        ComputerSystem =
            $ComputerSystem

        BIOS =
            $BIOS

        Processor =
            $Processor

        InstalledWindowsFeatures =
            $WindowsFeatureSummary

        BootConfiguration =
            $BootConfig
    }

    Identity = [ordered]@{

        CurrentIdentity =
            $CurrentIdentity

        LocalUsers =
            $LocalUsers

        LocalGroups =
            $LocalGroups

        LocalAdministrators =
            $LocalAdministrators

        PasswordPolicy =
            $PasswordPolicy

        UserRights =
            $UserRights

        CurrentUserPrivileges =
            $WhoAmIPrivileges

        CurrentUserGroups =
            $WhoAmIGroups
    }

    PrivilegeEscalation = [ordered]@{

        AlwaysInstallElevated =
            $AlwaysInstallElevated

        AutoLogon =
            $AutoLogon

        ServiceSecurity =
            $ServiceSecurity

        ScheduledTaskSecurity =
            $ScheduledTaskSecurity

        Autoruns =
            $Autoruns

        PathSecurity =
            $PathSecurity

        DLLSearchSecurity =
            $DLLSearchSecurity
    }

    EndpointProtection = [ordered]@{

        DefenderStatus =
            $DefenderStatus

        DefenderPreferences =
            $DefenderPreferences

        DefenderExclusions =
            $DefenderExclusions

        ASRRules =
            $ASRRules
    }

    Firewall = [ordered]@{

        Profiles =
            $FirewallProfiles

        EnabledInboundRules =
            $EnabledInboundFirewallRules

        BroadInboundRules =
            $BroadInboundFirewallRules
    }

    Network = [ordered]@{

        Adapters =
            $NetworkAdapters

        IPConfiguration =
            $IPConfiguration

        Routes =
            $Routes

        TCPListeners =
            $ListeningTCP

        UDPListeners =
            $ListeningUDP

        LegacyNameResolution =
            $LegacyNameResolution
    }

    SMB = [ordered]@{

        ServerConfiguration =
            $SMBServer

        ClientConfiguration =
            $SMBClient

        Shares =
            $Shares

        ShareAccess =
            $ShareAccess
    }

    Authentication = [ordered]@{

        NTLM =
            $NTLMSecurity

        LDAP =
            $LDAPSecurity

        UAC =
            $UAC

        CredentialProtection =
            $CredentialSecurity

        DeviceGuard =
            $DeviceGuard
    }

    RemoteAccess = [ordered]@{

        RDP =
            $RDPConfig

        WinRM =
            $WinRMService

        TrustedHosts =
            $TrustedHosts

        WinRMConfiguration =
            $WinRMConfig
    }

    ApplicationControl = [ordered]@{

        AppLockerService =
            $AppLockerService

        AppLockerCollections =
            $AppLockerCollections

        AppLockerRules =
            $AppLockerRules

        WDAC =
            $WDAC
    }

    Logging = [ordered]@{

        PowerShell =
            $PowerShellSecurity

        AuditPolicy =
            $AuditPolicy

        EventLogs =
            $EventLogs

        Sysmon =
            $Sysmon
    }

    Cryptography = [ordered]@{

        SchannelProtocols =
            $SchannelProtocols
    }

    PatchManagement = [ordered]@{

        InstalledHotFixes =
            $HotFixes

        PatchStatus =
            $PatchStatus

        PendingReboot =
            $PendingReboot

        AvailableWindowsUpdates =
            $AvailableWindowsUpdates
    }

    SoftwareDllAssessment =
        $SoftwareDllAssessment

    InstalledSoftware =
        $InstalledSoftware

    Processes =
        $Processes
}

# Optional checks run against the just-collected findings before reports are written.
Write-Host '[+] Creating separate host and DLL analysis reports'
Export-AssessmentReports -Assessment $Report -OutputDirectory $OutputDirectory -BaseName ([IO.Path]::GetFileNameWithoutExtension($JsonFile)) -RunVerification:$RunVerification -TimeoutSeconds $TimeoutSeconds
$SeveritySummary=$Report.SeveritySummary

# ============================================================================
# COMPLETE
# ============================================================================

$EndTime = Get-Date

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Assessment Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Critical:       $($SeveritySummary.Critical)" -ForegroundColor Red
Write-Host "High:           $($SeveritySummary.High)" -ForegroundColor Red
Write-Host "Medium:         $($SeveritySummary.Medium)" -ForegroundColor Yellow
Write-Host "Low:            $($SeveritySummary.Low)" -ForegroundColor Cyan
Write-Host "Informational:  $($SeveritySummary.Informational)" -ForegroundColor Gray
Write-Host ""

Write-Host "Started:   $StartTime"
Write-Host "Completed: $EndTime"
Write-Host ""

Write-Host "JSON:"
Write-Host "  $JsonFile"

Write-Host "TXT:"
Write-Host "  $TxtFile"

Write-Host "HTML:"
Write-Host "  $HtmlFile"

Write-Host "SHA256:"
Write-Host "  $HashFile"

Write-Host ""
