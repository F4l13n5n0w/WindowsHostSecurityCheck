#Requires -Version 5.1
# Local verification plans. Never execute Command or VerificationSteps from a report.
function New-VerificationStep {
    param([string]$Name, [string]$Command, [string]$Explanation)
    [pscustomobject]@{Name=$Name;Command=$Command;Explanation=$Explanation}
}

function Get-LocalVerificationPlan {
    param($Finding)
    $Steps=New-Object 'System.Collections.Generic.List[object]'
    $Title=[string]$Finding.Finding
    $Data=$Finding.EvidenceData
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
