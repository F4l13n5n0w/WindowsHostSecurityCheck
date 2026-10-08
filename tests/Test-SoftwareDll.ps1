#Requires -Version 5.1
param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'artifacts\software-dll'))
$ErrorActionPreference='Stop'
$SourcePath=Join-Path (Split-Path $PSScriptRoot -Parent) 'windows_security_check_v3.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw ($errors | Out-String)}
foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {. ([scriptblock]::Create($definition.Extent.Text))}
$script:Assertions=0;$script:Findings=@();$script:Errors=@()
function Assert-True([bool]$Condition,[string]$Message) {$script:Assertions++;if(-not $Condition){throw "FAILED: $Message"}}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
function New-PeFixture {
    param([string]$Path,[switch]$Pe64,[string]$Import='custom.dll',[string]$Delay='delayed.dll',[switch]$LegacyDelay)
    $bytes=New-Object byte[] 4096
    function Put16([int]$Offset,[uint16]$Value) {[BitConverter]::GetBytes($Value).CopyTo($bytes,$Offset)}
    function Put32([int]$Offset,[uint32]$Value) {[BitConverter]::GetBytes($Value).CopyTo($bytes,$Offset)}
    function Put64([int]$Offset,[uint64]$Value) {[BitConverter]::GetBytes($Value).CopyTo($bytes,$Offset)}
    Put16 0 0x5a4d;Put32 0x3c 0x80;Put32 0x80 0x4550
    Put16 0x84 $(if($Pe64){0x8664}else{0x14c});Put16 0x86 1
    $optional=0x98;$size=if($Pe64){240}else{224}
    Put16 0x94 $size;Put16 $optional $(if($Pe64){0x20b}else{0x10b})
    if($Pe64){Put64 ($optional+24) 0x140000000;$dataOffset=112;Put32 ($optional+108) 16}
    else{Put32 ($optional+28) 0x400000;$dataOffset=96;Put32 ($optional+92) 16}
    Put32 ($optional+60) 0x200
    Put32 ($optional+$dataOffset+8) 0x1100;Put32 ($optional+$dataOffset+12) 40
    Put32 ($optional+$dataOffset+104) 0x1300;Put32 ($optional+$dataOffset+108) 64
    $section=$optional+$size;Put32 ($section+8) 0x800;Put32 ($section+12) 0x1000;Put32 ($section+16) 0x800;Put32 ($section+20) 0x200
    Put32 0x30c 0x1200;[Text.Encoding]::ASCII.GetBytes($Import+[char]0).CopyTo($bytes,0x400)
    Put32 0x500 $(if($LegacyDelay){0}else{1});Put32 0x504 $(if($LegacyDelay){0x401400}else{0x1400})
    [Text.Encoding]::ASCII.GetBytes($Delay+[char]0).CopyTo($bytes,0x600)
    [IO.File]::WriteAllBytes($Path,$bytes)
}
$appRoot=Join-Path $OutputDirectory "App 'quoted"
New-Item -ItemType Directory -Path $appRoot -Force | Out-Null
$exe=Join-Path $appRoot 'example.exe';$dll=Join-Path $appRoot 'custom.dll'
New-PeFixture $exe;New-PeFixture $dll -Pe64
$before=(Get-FileHash -LiteralPath $exe).Hash
$pe=Get-PeDllImports $exe
Assert-True ($pe.Status -eq 'Collected' -and $pe.Architecture -eq 'x86') 'PE32 parsed'
Assert-True ($pe.Imports.Count -eq 2 -and $pe.Imports[0].DllName -eq 'custom.dll') 'Static and delay DLL names retained'
Assert-True (@($pe.Imports | Where-Object ImportKind -eq 'DelayImport').Count -eq 1) 'Delay import tagged'
$pe64=Get-PeDllImports $dll
Assert-True ($pe64.Status -eq 'Collected' -and $pe64.Architecture -eq 'x64') 'PE32+ parsed'
$legacy=Join-Path $appRoot 'legacy.exe';New-PeFixture $legacy -LegacyDelay
Assert-True ((Get-PeDllImports $legacy).Status -eq 'Collected') 'VA-based delay imports parsed'
Assert-True ((Get-FileHash -LiteralPath $exe).Hash -eq $before) 'PE parsing does not change contents'
$malformed=Join-Path $appRoot 'malformed.exe';[IO.File]::WriteAllBytes($malformed,[byte[]]@(77,90,0))
Assert-True ((Get-PeDllImports $malformed).Status -eq 'Unavailable') 'Truncated file explicitly unavailable'
$badRva=Join-Path $appRoot 'bad-rva.exe';New-PeFixture $badRva
$bytes=[IO.File]::ReadAllBytes($badRva);[BitConverter]::GetBytes([uint32]0x70000000).CopyTo($bytes,0x30c);[IO.File]::WriteAllBytes($badRva,$bytes)
Assert-True ((Get-PeDllImports $badRva).Status -eq 'Unavailable') 'Out-of-bounds import name rejected'
$pathImport=Join-Path $appRoot 'path-import.exe';New-PeFixture $pathImport -Import '..\outside.dll'
$api=Join-Path $appRoot 'api.exe';New-PeFixture $api -Import 'api-ms-win-core-test-l1-1-0.dll' -Delay 'kernel32.dll'
$unknownApp=[pscustomobject]@{DisplayName='Unknown path app';DisplayVersion='1';InstallLocation='';DisplayIcon='';InventorySource='Synthetic'}
$app=[pscustomobject]@{DisplayName='Example app';DisplayVersion='1';InstallLocation=$appRoot;InventorySource='Synthetic'}
$second=[pscustomobject]@{DisplayName='Second registration';DisplayVersion='2';InstallLocation=$appRoot;InventorySource='Synthetic'}
$remote=[pscustomobject]@{DisplayName='Remote root';InstallLocation='\\server\share';InventorySource='Synthetic'}
$broad=[pscustomobject]@{DisplayName='Drive root';InstallLocation=[IO.Path]::GetPathRoot($appRoot);InventorySource='Synthetic'}
& {
    function Test-Path {param($LiteralPath) $true}
    function Test-IsAdministrator {$false}
    function Get-ChildItem {
        param($LiteralPath)
        $key=[pscustomobject]@{Name=($LiteralPath+'\App');Values=@{DisplayName='Repeated app';DisplayVersion='1';InstallLocation=$appRoot;DisplayIcon=($exe+',0')}}
        $key | Add-Member ScriptMethod GetValue {param($Name) $this.Values[$Name]}
        $key
    }
    function Get-AppxPackage {param([switch]$AllUsers) if($AllUsers){throw 'Non-elevated test must not query AllUsers'}; [pscustomobject]@{Name='Packaged app';Version='2';Publisher='Synthetic';InstallLocation=$appRoot;PackageFullName='SyntheticPackage'}}
    $inventory=@(Get-InstalledSoftwareInventory)
    Assert-True ($inventory.Count -eq 5) 'Machine/user and both registry views retained along with AppX entries'
    Assert-True (@($inventory | Where-Object InventorySource -like 'HKCU:*').Count -eq 2) 'Current-user installed applications included'
    Assert-True (@($inventory | Where-Object DisplayName -eq 'Repeated app').Count -eq 4) 'Duplicate display names across locations are not silently discarded'
}
& {
    # Synthetic descriptors; the scanner must retain deny and inherit-only rules.
    $sid=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $allow=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::WriteData,[Security.AccessControl.AccessControlType]::Allow)
    $deny=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::WriteData,[Security.AccessControl.AccessControlType]::Deny)
    $inheritOnly=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::Modify,[Security.AccessControl.InheritanceFlags]::ContainerInherit,[Security.AccessControl.PropagationFlags]::InheritOnly,[Security.AccessControl.AccessControlType]::Allow)
    function Get-Acl {param($LiteralPath) [pscustomobject]@{Owner='Synthetic';Sddl='synthetic';Access=@($allow,$deny,$inheritOnly)}}
    $acl=Get-SoftwareDllAcl $appRoot
    Assert-True ($acl.Rules.Count -eq 3 -and $acl.Rules[0].BroadWriteAllow) 'SID-based broad Allow ACE recognized'
    Assert-True (-not $acl.Rules[1].BroadWriteAllow -and $acl.Rules[1].AccessControlType -eq 'Deny') 'Deny ACE preserved without being flagged as grant'
    Assert-True (-not $acl.Rules[2].BroadWriteAllow -and -not $acl.Rules[2].AppliesToObject) 'Inherit-only grant excluded for current object'
    $admin=[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $adminAllow=[Security.AccessControl.FileSystemAccessRule]::new($admin,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)
    $readOnly=[Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::ReadAndExecute,[Security.AccessControl.AccessControlType]::Allow)
    function Get-Acl {param($LiteralPath) [pscustomobject]@{Owner='Synthetic';Sddl='synthetic';Access=@($adminAllow,$readOnly)}}
    Assert-True (-not (Get-SoftwareDllAcl $appRoot).BroadWriteAllow) 'Admin FullControl and broad read-only permissions are not broad mutation candidates'
}
& {
    function Get-KnownSoftwareDllNames {@('kernel32.dll')}
    function Get-SoftwareDllAcl {param([string]$Path) [pscustomobject]@{Path=$Path;Status='Collected';Rules=@([pscustomobject]@{Sid='S-1-5-32-545';BroadWriteAllow=$true;Rights='Modify';AccessControlType='Allow'});BroadWriteAllow=$true;Error=$null}}
    function Get-SoftwareProcessAccess {param([int]$ProcessId,[string]$ExpectedPath) [pscustomobject]@{ProcessId=$ProcessId;ExpectedPath=$ExpectedPath;ImageMatchesExpected=$true;InjectionRightsGranted=$true;HigherIntegrity=($ProcessId -in @(99,96));DifferentUser=($ProcessId -in @(99,96));CallerIsAdministrator=($ProcessId -eq 96);CallerIntegrityRid=if($ProcessId -eq 96){12288}else{8192};TargetIntegrityRid=if($ProcessId -in @(99,96)){16384}else{8192};Explanation='Synthetic handle-only access check'}}
    $script:Findings=@()
    $result=Get-InstalledSoftwareDllAssessment -Software @($app,$second,$unknownApp,$remote,$broad) -Processes @([pscustomobject]@{Id=99;Path=$exe},[pscustomobject]@{Id=98;Path=$exe},[pscustomobject]@{Id=96;Path=$exe},[pscustomobject]@{Id=97;Path=($appRoot+'Other\evil.exe')}) -Services @([pscustomobject]@{Name='Svc';Executable=$exe;StartName='LocalSystem'}) -TimeoutSeconds 30
    Assert-True ($result.Applications.Count -eq 5) 'Every inventory entry has a coverage row'
    Assert-True ($result.Applications[0].Status -eq 'Partial') 'Malformed binary creates partial coverage'
    Assert-True ($result.Applications[0].ReviewOutcome -eq 'CandidatesForReview' -and $result.Applications[0].Explanation -notmatch 'No candidate observed') 'Candidate summary does not contradict the recorded findings'
    Assert-True ($result.Applications[2].Status -eq 'NotAssessed') 'Missing installation root is not a pass'
    Assert-True ($result.Applications[3].Status -eq 'Unavailable' -and $result.Applications[4].Status -eq 'Unavailable') 'UNC and overly broad roots rejected'
    $candidates=@($result.Applications[0].DllCandidates)
    Assert-True (@($candidates | Where-Object DllName -like 'api-ms-*').Count -eq 0) 'API sets excluded from filename-planting candidates'
    Assert-True (@($candidates | Where-Object DllName -eq 'kernel32.dll').Count -eq 0) 'KnownDLL imports excluded'
    Assert-True (@($candidates | Where-Object DllName -like '*outside.dll').Count -eq 0) 'Relative/path-bearing import names are not filesystem targets'
    Assert-True (@($candidates | Where-Object CandidateKind -eq 'WritableExistingDll').Count -gt 0) 'Writable existing DLL candidate recorded'
    Assert-True (@($candidates | Where-Object CandidateKind -eq 'MissingAppLocalImport').Count -gt 0) 'Missing app-local import candidate recorded'
    Assert-True ($result.Applications[0].RegisteredConsumers[0].RunAs -eq 'LocalSystem') 'Registered consumer identity retained'
    Assert-True ($result.Applications[0].ProcessAccessChecks.Count -eq 3) 'Only processes inside the root path boundary checked'
    $injectionFindings=@($script:Findings | Where-Object Finding -like 'Installed software process injection access:*')
    Assert-True ($injectionFindings.Count -eq 2 -and $injectionFindings[0].EvidenceData.ProcessId -eq 99) 'Non-elevated higher-integrity access flagged; same-context and elevated admin access not labeled vulnerabilities'
    Assert-True (@($script:Findings | Where-Object Status -ne 'Review').Count -eq 0) 'All candidates marked Review'
    $limited=Get-InstalledSoftwareDllAssessment -Software @($app) -MaxFilesPerSoftware 1
    Assert-True ($limited.Applications[0].Status -eq 'Partial' -and $limited.Applications[0].EntriesExamined -eq 1) 'File budget explicit without silently passing'
    $candidateLimited=Get-InstalledSoftwareDllAssessment -Software @($app) -MaxCandidatesPerSoftware 1
    Assert-True ($candidateLimited.Applications[0].Status -eq 'Partial' -and $candidateLimited.Applications[0].DllCandidateCount -eq 1 -and $candidateLimited.Applications[0].Explanation -match 'budget') 'Candidate budget bounds report size and reports incomplete coverage'
    $skipped=Get-InstalledSoftwareDllAssessment -Software @($app,$unknownApp) -Skip
    Assert-True ($skipped.Applications.Count -eq 2 -and $skipped.Applications[0].Status -eq 'Skipped') 'Skipping retains inventory rows'
    $iconApp=[pscustomobject]@{DisplayName='Icon-inferred app';InstallLocation='';DisplayIcon=('"'+$exe+'",0')}
    $inferred=Get-InstalledSoftwareDllAssessment -Software @($iconApp)
    Assert-True ($inferred.Applications[0].InstallRoot -eq $appRoot -and $inferred.Applications[0].RootSource -match 'inferred') 'Executable DisplayIcon can provide a clearly labeled inferred root'
    $emptyRoot=Join-Path $OutputDirectory 'empty-app';New-Item -ItemType Directory -Path $emptyRoot -Force | Out-Null
    $empty=Get-InstalledSoftwareDllAssessment -Software @([pscustomobject]@{DisplayName='No binary app';InstallLocation=$emptyRoot})
    Assert-True ($empty.Applications[0].Status -eq 'NoBinaryData') 'No EXE/DLL data is not a pass'
    $sample=[ordered]@{Metadata=@{Host='Synthetic';Version='3.1'};SeveritySummary=@{Critical=0;High=1;Medium=$script:Findings.Count;Low=0;Informational=0};Findings=$script:Findings;SoftwareDllAssessment=$result}
    $html=New-AssessmentHtml $sample
    Assert-True ($html -match 'Software Dll Assessment' -and $html -match 'issue-highlight') 'Report includes DLL group and highlighted risk evidence'
    $html | Set-Content -LiteralPath (Join-Path $OutputDirectory 'software-dll-report.html') -Encoding UTF8
    $sample | ConvertTo-Json -Depth 100 -WarningAction Stop | Set-Content -LiteralPath (Join-Path $OutputDirectory 'software-dll-report.json') -Encoding UTF8
}
# Live native bridge smoke test on this test process only; no injection operation.
$selfPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$self=Get-SoftwareProcessAccess -ProcessId $PID -ExpectedPath $selfPath
Assert-True ($self.ImageMatchesExpected -and $self.InjectionRightsGranted) 'Own-process access query returns matching image'
Assert-True ($self.CallerIntegrityRid -ge 0 -and $self.TargetIntegrityRid -eq $self.CallerIntegrityRid -and -not $self.HigherIntegrity -and -not $self.DifferentUser) 'Native probe reads token context without inventing privilege gain'
$invalid=Get-SoftwareProcessAccess -ProcessId 2147483647 -ExpectedPath $selfPath
Assert-True (-not $invalid.InjectionRightsGranted -and -not $invalid.ImageMatchesExpected -and $invalid.OpenProcessError -ne 0) 'Exited/nonexistent process is not a confirmed access issue'
$wrongImage=Get-SoftwareProcessAccess -ProcessId $PID -ExpectedPath $exe
Assert-True (-not $wrongImage.ImageMatchesExpected) 'PID image mismatch invalidates target association'
$data=[pscustomobject]@{BinaryPath=$exe;DllPath=$dll;ProcessId=$PID}
foreach ($inject in @($false,$true)) {
    $plan=@(Get-SoftwareDllVerificationPlan $data -Injection:$inject)
    $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($plan[0].Command,[ref]$tokens,[ref]$errors)
    Assert-True ($errors.Count -eq 0) 'Standalone verification commands parse with apostrophes in paths'
    $execution=Invoke-VerificationStep $plan[0] 30
    Assert-True ($execution.Status -eq 'Completed') 'Standalone verification runspace executes trusted function definitions'
}
Assert-True ((Get-FileHash -LiteralPath $exe).Hash -eq $before) 'Assessment and verification did not change executable'
Assert-True (-not (Test-Path -LiteralPath (Join-Path $appRoot 'delayed.dll'))) 'Missing dependency was not planted'
Write-Host "PASS: $script:Assertions software DLL assertions on PowerShell $($PSVersionTable.PSVersion). Artifacts: $OutputDirectory"
