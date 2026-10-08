param([string]$OutputDirectory = (Join-Path $PSScriptRoot 'artifacts'), [string]$SourceName='windows_security_check_v3.ps1')
$ErrorActionPreference = 'Stop'
$SourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) $SourceName
$Tokens = $null
$ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw ($ParseErrors | Out-String) }
# Load function definitions only. Never dot-source the assessment's main program.
$Definitions = @($Ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true))
foreach ($Definition in $Definitions) { . ([scriptblock]::Create($Definition.Extent.Text)) }
$script:Assertions = 0
$script:Errors = @()
$script:Findings = @()
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:Assertions++
    if (-not $Condition) { throw "FAILED: $Message" }
}
function Assert-Parses {
    param([string]$Code, [string]$Label)
    $t=$null; $e=$null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$t, [ref]$e)
    Assert-True ($e.Count -eq 0) "$Label parses"
}

Assert-True (-not (Test-ServiceSddlWeak 'D:(A;;CCLCSWLOCRRC;;;WD)')) 'Everyone read-only ACE is not flagged'
Assert-True (-not (Test-ServiceSddlWeak 'D:(D;;GA;;;AU)')) 'Deny ACE is not flagged as a grant'
Assert-True (Test-ServiceSddlWeak 'D:(A;;DC;;;AU)') 'SERVICE_CHANGE_CONFIG is flagged'
Assert-True (Test-ServiceSddlWeak 'D:(A;;WD;;;BU)') 'WRITE_DAC is flagged'
Assert-True (Test-ServiceSddlWeak 'D:(A;;GW;;;AU)') 'GENERIC_WRITE is flagged'
Assert-True (-not (Test-ServiceSddlWeak 'D:(A;;GA;;;BA)')) 'Administrators-only grant is not flagged'
Assert-True (-not (Test-ServiceSddlWeak 'D:(A;;RPWP;;;AU)')) 'Start and stop rights alone are not modification rights'
$null = Test-ServiceSddlWeak 'invalid sddl'
Assert-True ($script:Errors.Count -eq 1) 'Malformed descriptor is recorded'
$script:Errors=@()
$null = Invoke-SafeCommand 'Synthetic error' { Write-Error 'synthetic failure' }
Assert-True ($script:Errors.Count -eq 1) 'Nonterminating errors reach collection error handler'

# Prove the AutoLogon presence helper uses names, never values.
& {
    function Test-Path { param($LiteralPath,$Path) return $true }
    function Get-Item {
        param($LiteralPath)
        $Key=[pscustomobject]@{}
        $Key | Add-Member ScriptMethod GetValueNames { @('DefaultPassword','OtherValue') }
        $Key | Add-Member ScriptMethod GetValue { throw 'Credential value must not be retrieved' }
        return $Key
    }
    function Get-ItemProperty { throw 'Credential value must not be retrieved' }
    Assert-True (Test-RegistryValueExists 'HKLM:\Synthetic' 'DefaultPassword') 'Registry presence check does not read contents'
    Assert-True (-not (Test-RegistryValueExists 'HKLM:\Synthetic' 'Missing')) 'Missing registry value returns false'
}

$row=Invoke-LocalCheck -Name 'Unavailable test' -Command 'Get-SyntheticData' -Collect { throw 'Access denied' }
Assert-True ($row.Status -eq 'Unavailable') 'Failed collection is explicitly unavailable'
$row=Invoke-LocalCheck -Name 'Empty test' -Command 'Get-SyntheticData' -Collect { }
Assert-True ($row.Status -eq 'No data') 'Empty collection is not a pass'
$row=Invoke-LocalCheck -Name 'Partial test' -Command 'Get-SyntheticData' -Collect { Add-CollectionError 'one object' 'denied'; 'other object' }
Assert-True ($row.Status -eq 'Partial') 'Per-object failures mark collection partial'
$row=Invoke-LocalCheck -Name 'Unsupported test' -RequiredCommand '__NonexistentAssessmentCommand__' -Command '__NonexistentAssessmentCommand__' -Collect { throw 'Should not run' }
Assert-True ($row.Status -eq 'Unavailable') 'Missing module is explicitly unavailable'

# Register checks without running any collector.
$script:RegisteredChecks=@()
& {
    function Invoke-LocalCheck {
        param($Name,$Command,$Collect,$Evaluate,$RequiredCommand)
        $script:RegisteredChecks += [pscustomobject]@{Name=$Name;Command=$Command;Collect=$Collect;Evaluate=$Evaluate}
    }
    Get-AdditionalHostChecks
}
Assert-True ($RegisteredChecks.Count -eq 18) '18 additional check groups registered'
foreach ($Check in $RegisteredChecks) {
    Assert-True (-not [string]::IsNullOrWhiteSpace($Check.Command)) "$($Check.Name) has a repeatable command"
    Assert-Parses $Check.Command $Check.Name
}
function Test-Evaluator {
    param($Name,$Data,[int]$Expected)
    $script:Findings=@()
    $Check=$RegisteredChecks | Where-Object Name -eq $Name
    & $Check.Evaluate @($Data) $Check.Command
    Assert-True ($script:Findings.Count -eq $Expected) "$Name expected $Expected findings"
    foreach ($Finding in $script:Findings) {
        Assert-True ($Finding.Command -eq $Check.Command) "$Name retains collection command"
    }
}
Test-Evaluator 'Point and Print policy' ([pscustomobject]@{RestrictDriverInstallationToAdministrators=0}) 1
Test-Evaluator 'Point and Print policy' ([pscustomobject]@{RestrictDriverInstallationToAdministrators=$null}) 0
Test-Evaluator 'Point and Print policy' ([pscustomobject]@{RestrictDriverInstallationToAdministrators=1;NoWarningNoElevationOnInstall=1}) 0
Test-Evaluator 'WSUS transport policy' ([pscustomobject]@{UseWUServer=1;WUServer='http://updates.example.test'}) 1
Test-Evaluator 'WSUS transport policy' ([pscustomobject]@{UseWUServer=0;WUServer='http://updates.example.test'}) 0
Test-Evaluator 'WSUS transport policy' ([pscustomobject]@{UseWUServer=1;WUServer='https://updates.example.test'}) 0
Test-Evaluator 'Secure Boot' ([pscustomobject]@{Enabled=$false}) 1
Test-Evaluator 'Secure Boot' ([pscustomobject]@{Enabled=$true}) 0
Test-Evaluator 'BitLocker volume protection' ([pscustomobject]@{MountPoint='C:';VolumeType='OperatingSystem';ProtectionStatus='Off'}) 1
Test-Evaluator 'BitLocker volume protection' ([pscustomobject]@{MountPoint='C:';VolumeType='OperatingSystem';ProtectionStatus='On'}) 0
Test-Evaluator 'BitLocker volume protection' ([pscustomobject]@{MountPoint='D:';VolumeType='Data';ProtectionStatus='Off'}) 0
Test-Evaluator 'PowerShell optional features' ([pscustomobject]@{FeatureName='MicrosoftWindowsPowerShellV2';State='Enabled'}) 1
Test-Evaluator 'PowerShell optional features' ([pscustomobject]@{FeatureName='MicrosoftWindowsPowerShellV2';State='Disabled'}) 0
Test-Evaluator 'Process command-line audit policy' ([pscustomobject]@{ProcessCreationIncludeCmdLine_Enabled=0}) 1
Test-Evaluator 'Process command-line audit policy' ([pscustomobject]@{ProcessCreationIncludeCmdLine_Enabled=$null}) 0
Test-Evaluator 'Image File Execution Options debuggers' ([pscustomobject]@{PSPath='HKLM:\Synthetic';Debugger='debugger.exe'}) 1
Test-Evaluator 'Permanent WMI subscription bindings' ([pscustomobject]@{Filter='filter';Consumer='consumer'}) 1
Test-Evaluator 'Startup folders and broad write permissions' ([pscustomobject]@{Path='C:\Startup';BroadWriteAces=@()}) 0
Test-Evaluator 'Startup folders and broad write permissions' ([pscustomobject]@{Path='C:\Startup';BroadWriteAces=@('Allow Users Write')}) 1
Test-Evaluator 'Unattended setup file metadata' ([pscustomobject]@{FullName='C:\unattend.xml';Length=123}) 1

# Exercise existing account conditions directly, without host collection.
$Source=Get-Content -LiteralPath $SourcePath -Raw
$AccountStart=$Source.IndexOf('$Guest =')
$AccountEnd=$Source.IndexOf('# ADDITIONAL LOCAL CHECKS', $AccountStart)
$AccountCode=$Source.Substring($AccountStart,$AccountEnd-$AccountStart)
$LocalUsers=@([pscustomobject]@{Name='RenamedGuest';SID=[pscustomobject]@{Value='S-1-5-21-1-501'};Enabled=$true})
$PasswordPolicy=[pscustomobject]@{MinimumPasswordLength='0';ClearTextPassword='0';LockoutBadCount='5'}
$script:Findings=@()
. ([scriptblock]::Create($AccountCode))
Assert-True (@($Findings | Where-Object Finding -like 'Minimum password*').Count -eq 1) 'Zero minimum password length is flagged'
Assert-True (@($Findings | Where-Object Finding -like 'Built-in Guest*').Count -eq 1) 'Renamed Guest identified by SID'
$PasswordPolicy.MinimumPasswordLength=$null
$LocalUsers=@()
$script:Findings=@()
. ([scriptblock]::Create($AccountCode))
Assert-True ($Findings.Count -eq 0) 'Missing password policy is not treated as zero'

# Every finding call must carry a command argument. Parse generated existing commands
# with realistic paths containing apostrophes to verify shell quoting.
$Service=[pscustomobject]@{Name="O'Brien"}
$Profile=[pscustomobject]@{Name='Domain'}
$Ace=[pscustomobject]@{Share="O'Brien"}
$Executable="C:\Apps\O'Brien\app.exe"; $Directory="C:\Apps\O'Brien"; $Parent=$Directory
$TaskFile="C:\Windows\System32\Tasks\O'Brien"; $ActionExecutable=$Executable; $ExpandedPath=$Directory
$RegistryPath="HKLM:\SYSTEM\CurrentControlSet\Services\O'Brien"
$UacPath='HKLM:\Software\Synthetic'; $LsaPath=$UacPath; $RdpBase=$UacPath; $RdpTcp=$UacPath; $Protocol='TLS 1.0'
$Calls=@($Ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Finding'},$true))
foreach ($Call in $Calls) {
    $Parameters=@($Call.CommandElements | Where-Object {$_ -is [System.Management.Automation.Language.CommandParameterAst]})
    Assert-True (@($Parameters | Where-Object ParameterName -eq 'Command').Count -eq 1) "Finding line $($Call.Extent.StartLineNumber) has command"
    Assert-True (@($Parameters | Where-Object ParameterName -eq 'EvidenceData').Count -eq 1) "Finding line $($Call.Extent.StartLineNumber) preserves source evidence"
    $Context = Get-ExploitationContext $Call.CommandElements[3].Value ''
    Assert-True (-not $Context.StartsWith('No direct exploitation path')) "Finding line $($Call.Extent.StartLineNumber) has specific abuse context"
    $Owner=$Call.Parent
    while ($Owner -and $Owner -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $Owner=$Owner.Parent }
    if (-not $Owner) {
        for ($i=0;$i -lt $Call.CommandElements.Count;$i++) {
            if ($Call.CommandElements[$i] -is [System.Management.Automation.Language.CommandParameterAst] -and $Call.CommandElements[$i].ParameterName -eq 'Command') {
                $Generated=& ([scriptblock]::Create($Call.CommandElements[$i+1].Extent.Text))
                Assert-Parses $Generated "Finding line $($Call.Extent.StartLineNumber) command"
            }
        }
    }
}

# Evidence must not depend on terminal width, FormatEnumerationLimit, or default views.
$LongValue=('abcdef' * 3000) + 'END-OF-LONG-EVIDENCE'
$EvidenceFixture=[pscustomobject]@{
    LongPath=$LongValue
    Entries=@(1..20 | ForEach-Object { [pscustomobject]@{Index=$_;Value="Full evidence row $_"} })
    Nested=[pscustomobject]@{Child=[pscustomobject]@{Value='DEEPEST-RETAINED'}}
}
$EvidenceText=Convert-ToSafeString $EvidenceFixture
$EvidenceRoundTrip=$EvidenceText | ConvertFrom-Json
Assert-True ($EvidenceRoundTrip.LongPath -ceq $LongValue) 'Long evidence strings survive unchanged'
Assert-True ($EvidenceRoundTrip.Entries.Count -eq 20) 'All evidence array entries retained'
Assert-True ($EvidenceRoundTrip.Entries[-1].Value -eq 'Full evidence row 20') 'Final evidence record retained'
Assert-True ($EvidenceRoundTrip.Nested.Child.Value -eq 'DEEPEST-RETAINED') 'Nested evidence retained'
Assert-True ((Convert-ArrayToText $EvidenceFixture).Contains('END-OF-LONG-EVIDENCE')) 'TXT formatting does not clip fields'
$MixedHtml=ConvertTo-ReportValueHtml @('plain text',$EvidenceFixture)
Assert-True ($MixedHtml.Contains('END-OF-LONG-EVIDENCE')) 'Mixed scalar/object evidence is serialized completely'
$DifferentFields=ConvertTo-ReportValueHtml @([pscustomobject]@{First='a'},[pscustomobject]@{First='b';LaterField='RETAIN-LATER-FIELD'})
Assert-True ($DifferentFields.Contains('RETAIN-LATER-FIELD')) 'Later records cannot lose additional columns'
$script:Findings=@()
Add-Finding 'High' 'Test' 'Service executable is writable by a broad principal: Example' 'Review' 'One-line observation' 'Review permissions.' -Command 'Get-Acl C:\Example.exe' -EvidenceData $EvidenceFixture
Assert-True ($Findings[0].EvidenceSummary -eq 'One-line observation') 'Observation remains separate from full evidence'
Assert-True ($Findings[0].Evidence.Contains('END-OF-LONG-EVIDENCE')) 'Finding contains complete serialized evidence'
Assert-True ($Findings[0].EvidenceData.Entries.Count -eq 20) 'JSON finding preserves structured source evidence'
Assert-True ($Findings[0].HowToExploit -match 'service account') 'Finding has scenario-specific exploitation context'
$FixtureFinding=$Findings[0]

# Next-step commands are generated from saved data, never executed by these tests.
$VerificationCases=@(
    @('Scheduled task definition is broadly writable: MareBackup', [pscustomobject]@{TaskName="O'Brien";TaskPath='\Microsoft\Windows\Application Experience\';TaskFile="C:\Tasks\O'Brien"}),
    @('Scheduled task executable is broadly writable: Example', [pscustomobject]@{TaskName='Example';TaskPath='\';Action="C:\Apps\O'Brien.exe"}),
    @('Scheduled task executable directory is broadly writable: Example', [pscustomobject]@{TaskName='Example';TaskPath='\';Action='C:\Apps\Example.exe'}),
    @('Service executable is writable by a broad principal: Example', [pscustomobject]@{Name="O'Brien";Executable="C:\Apps\O'Brien.exe"}),
    @('Service executable directory is writable by a broad principal: Example', [pscustomobject]@{Name='Example';Directory='C:\Apps'}),
    @('Service registry configuration is writable by a broad principal: Example', [pscustomobject]@{Name="O'Brien"}),
    @('Potentially broad service-object permissions: Example', [pscustomobject]@{Name='Example'}),
    @('Unquoted service executable path: Example', [pscustomobject]@{Name='Example';Executable='C:\Program Files\Example\service.exe'}),
    @('Autorun executable is broadly writable: Example', [pscustomobject]@{RegistryPath='HKCU:\SOFTWARE\Example';Executable='C:\Apps\Example.exe'}),
    @('Autorun executable directory is broadly writable: Example', [pscustomobject]@{RegistryPath='HKLM:\SOFTWARE\Example';Executable='C:\Apps\Example.exe'}),
    @('System PATH directory is broadly writable', [pscustomobject]@{Path="C:\O'Brien"}),
    @('Startup folder has broad write permissions: Example', [pscustomobject]@{Path='C:\Startup'}),
    @('AlwaysInstallElevated is enabled', [pscustomobject]@{}),
    @('Sensitive user right configured: SeBackupPrivilege', [pscustomobject]@{}),
    @('Safe DLL search mode is disabled', [pscustomobject]@{}),
    @('Image File Execution Options debugger is configured', [pscustomobject]@{})
)
foreach ($Case in $VerificationCases) {
    $Steps=Get-FindingVerificationSteps $Case[0] 'Privilege Escalation' $Case[1] 'Get-Item C:\Example'
    Assert-Parses $Steps "Verification: $($Case[0])"
    Assert-True ($Steps.Contains('whoami.exe /all')) 'Verification includes tested identity'
    $t=$null;$e=$null
    $StepsAst=[System.Management.Automation.Language.Parser]::ParseInput($Steps,[ref]$t,[ref]$e)
    $StepCalls=@($StepsAst.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true))
    Assert-True (@($StepCalls | Where-Object {$_.GetCommandName() -match '^(Set-|Start-|Stop-|Register-|Unregister-|Remove-|Invoke-Expression)'}).Count -eq 0) 'Verification does not remediate or execute privileged targets'
}
$TaskSteps=Get-FindingVerificationSteps $VerificationCases[0][0] 'Privilege Escalation' $VerificationCases[0][1] ''
Assert-True ($TaskSteps.Contains('TrimEnd([char]92)')) 'COM folder query removes trailing backslash'
Assert-True ($TaskSteps.Contains('finally {')) 'Write handle is disposed in the same statement'
Assert-True ($TaskSteps.Contains('[System.IO.FileMode]::Open')) 'Write probe opens an existing file without truncating'
Assert-True (-not $TaskSteps.Contains('WriteAll')) 'Write probe does not write file bytes'
Assert-True ((Get-FindingVerificationSteps 'Unrelated finding' 'Firewall' $null '').Length -eq 0) 'Unrelated findings do not receive invented escalation steps'

# Exercise the collector's task loop with synthetic data to check action deduplication.
& {
    $FakeTask=[pscustomobject]@{
        TaskName='Example';TaskPath='\';State='Ready'
        Principal=[pscustomobject]@{UserId=$null;GroupId='S-1-5-4';LogonType='Group';RunLevel=1}
        Settings=[pscustomobject]@{Enabled=$true;AllowDemandStart=$true}
        Actions=@([pscustomobject]@{Execute=$null;ClassId='{example-1}'},[pscustomobject]@{Execute=$null;ClassId='{example-2}'})
        Triggers=@()
    }
    function Get-ScheduledTask { return $FakeTask }
    function Get-WeakAclEntries { param($Path) return [pscustomobject]@{Path=$Path;Identity='BUILTIN\Users';Rights='FullControl';Inherited=$false} }
    $script:Findings=@()
    $TaskStart=$Source.IndexOf('$ScheduledTaskSecurity = @()')
    $TaskEnd=$Source.IndexOf('# AUTORUNS', $TaskStart)
    . ([scriptblock]::Create($Source.Substring($TaskStart,$TaskEnd-$TaskStart)))
    Assert-True ($Findings.Count -eq 1) 'A two-action task has one task-definition finding'
    Assert-True ($Findings[0].Status -eq 'Review') 'Broad task grant is review, not confirmed execution'
    Assert-True ($Findings[0].EvidenceData.GroupId -eq 'S-1-5-4') 'Task group principal is retained'
    Assert-True ($Findings[0].EvidenceData.Actions.Count -eq 2) 'Task finding retains all actions'
    Assert-True ($Findings[0].EvidenceData.Actions[0].ClassId -eq '{example-1}') 'COM handler identity is retained'
    Assert-True ($Findings[0].VerificationSteps.Contains('GetSecurityDescriptor(7)')) 'Task finding includes scheduler verification'
}

# Red highlights target the relevant value, not every property or the command.
$HighlightCases=@(
    @('Microsoft Defender real-time protection is disabled','"RealTimeProtectionEnabled": false', $true),
    @('Microsoft Defender real-time protection is disabled','"RealTimeProtectionEnabled": true', $false),
    @('Microsoft Defender real-time protection is disabled','"AntivirusEnabled": false', $false),
    @('Minimum password length is below 14 characters','"MinimumPasswordLength": "0"', $true),
    @('Minimum password length is below 14 characters','"MinimumPasswordLength": "14"', $false),
    @('Minimum password length is below 14 characters','"MinimumPasswordLength": null', $false),
    @('Service executable is writable by a broad principal: Example','"Rights": "Modify, Synchronize"', $true),
    @('Service executable is writable by a broad principal: Example','"Rights": "ReadAndExecute"', $false),
    @('Service executable is writable by a broad principal: Example','"Name": "Modify"', $false),
    @('Configured WSUS update service uses HTTP','"WUServer": "http://updates.example.test"', $true),
    @('Configured WSUS update service uses HTTP','"WUServer": "https://updates.example.test"', $false),
    @('UEFI Secure Boot is disabled','"Enabled": false', $true),
    @('UEFI Secure Boot is disabled','"Enabled": true', $false),
    @('WinRM TrustedHosts permits all hosts','*', $true),
    @('WinRM TrustedHosts permits all hosts','server.example.test', $false),
    @('BitLocker protection is off on OS volume C:','"ProtectionStatus": 0', $true),
    @('BitLocker protection is off on OS volume C:','"ProtectionStatus": 1', $false),
    @('Security event log maximum size is below 1 GB','"MaximumSizeInBytes": 1024', $true),
    @('Security event log maximum size is below 1 GB','"MaximumSizeInBytes": 1073741824', $false)
)
foreach ($Case in $HighlightCases) {
    Assert-True ((Test-EvidenceIssueLine $Case[0] $Case[1]) -eq $Case[2]) "Highlight condition: $($Case[0]) / $($Case[1])"
}
$HighlightFinding=[pscustomobject]@{
    Finding='Service executable is writable by a broad principal: Example'
    Command="Get-Acl -LiteralPath 'C:\Example.exe'"
    EvidenceSummary='Broad Modify permission.'
    Evidence=Convert-ToSafeString ([pscustomobject]@{Rights='Modify <script>alert(9)</script>';Name='Keep this visible'})
}
$HighlightHtml=ConvertTo-FindingEvidenceHtml $HighlightFinding
Assert-True ($HighlightHtml.Contains('PS&gt; Get-Acl')) 'Evidence contains the command prompt and command'
Assert-True ($HighlightHtml.Contains('Collected response (selected fields)')) 'Evidence contains the saved response label'
Assert-True ($HighlightHtml.Contains('<mark class="issue-highlight"')) 'Triggering evidence is marked'
$MarkedLine=[regex]::Match($HighlightHtml, '<mark[^>]*>(.*?)</mark>').Groups[1].Value
$DecodedLine=[System.Net.WebUtility]::HtmlDecode($MarkedLine).Trim().TrimEnd(',')
$DecodedEvidence=('{' + $DecodedLine + '}') | ConvertFrom-Json
Assert-True ($DecodedEvidence.Rights -ceq 'Modify <script>alert(9)</script>') 'Highlighted hostile evidence round-trips without loss'
Assert-True (-not $HighlightHtml.Contains('<script>alert(9)</script>')) 'Highlight markup cannot introduce executable HTML'
Assert-True ($HighlightHtml.Contains('Keep this visible')) 'Unhighlighted evidence is retained'
$HighlightFinding.Command="Get-Acl C:\Example.exe" + [Environment]::NewLine + "Get-Service Example"
Assert-True ((ConvertTo-FindingEvidenceHtml $HighlightFinding).Contains('&gt;&gt; Get-Service Example')) 'Multiline command is preserved'
$HighlightFinding.Finding='Sysmon service was not detected'
$HighlightFinding.Evidence=''
Assert-True ((ConvertTo-FindingEvidenceHtml $HighlightFinding).Contains('issue-observation')) 'Missing-data trigger highlights the observation'

# Offline sample contains only invented data.
$script:Findings=@()
foreach ($Severity in @('Low','High','Informational','Critical','Medium')) {
    Add-Finding $Severity 'Synthetic examples' "$Severity example finding" 'Review' ("Setting=0" + [Environment]::NewLine + "Path=C:\Apps\Example") 'Review this synthetic configuration.' -Command "Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Example' -Name Setting"
}
$ExampleService=$Findings | Where-Object Severity -eq 'High'
$ExampleService.Finding='Service executable is writable by a broad principal: ExampleService'
$ExampleService.Category='Privilege Escalation'
$ExampleService.HowToExploit=Get-ExploitationContext 'Service executable is writable by a broad principal: ExampleService' ''
$ExampleService.EvidenceSummary='Synthetic example: broad write permission on a service executable.'
$ExampleService.EvidenceData=[pscustomobject]@{
    Name='ExampleService';StartName='LocalSystem';Executable='C:\Apps\Example\service.exe'
    WeakBinaryAcl=@([pscustomobject]@{Identity='BUILTIN\Users';Rights='Modify';Inherited=$false})
}
$ExampleService.Evidence=Convert-ToSafeString $ExampleService.EvidenceData
$ExampleService.Command="(Get-Acl -LiteralPath 'C:\Apps\Example\service.exe').Access"
$ExampleService.VerificationSteps=Get-FindingVerificationSteps $ExampleService.Finding $ExampleService.Category $ExampleService.EvidenceData $ExampleService.Command
Add-Finding 'Medium' 'Encoding test' '<img src=x onerror=alert(1)>' 'Review' '</code></pre><script>alert(1)</script>' 'Text must stay text.' -Command "Write-Output '<script>literal</script>'" -HowToExploit '<img src=x onerror=alert(2)>' -VerificationSteps 'Get-Item ''</code><script>alert(3)</script>'''
$Sample=[ordered]@{
    Metadata=[ordered]@{Host='SYNTHETIC-HOST';CurrentUser='EXAMPLE\Reviewer';AssessmentStarted='2026-10-01 12:00';Elevated=$false}
    SeveritySummary=[pscustomobject]@{Critical=1;High=1;Medium=2;Low=1;Informational=1;Total=6}
    Findings=$Findings
    CollectionErrors=@([pscustomobject]@{Component='Optional synthetic check';Error='Unavailable on this example host'})
    AdditionalChecks=@([pscustomobject]@{Check='Secure Boot';Status='Collected';Command='Confirm-SecureBootUEFI';Evidence=@([pscustomobject]@{Enabled=$false});Note='Synthetic data'})
    System=[ordered]@{OperatingSystem=[pscustomobject]@{Caption='Synthetic Windows';Build='Example'};Empty=@();Missing=$null}
}
$Html=New-AssessmentHtml $Sample
Assert-True ($Html.Contains([string][char]0x25B2)) 'Unicode sort indicator survives Windows PowerShell source decoding'
Assert-True ($Html.IndexOf('Critical example') -lt $Html.IndexOf('Service executable is writable')) 'Default severity order'
Assert-True ($Html.IndexOf('Service executable is writable') -lt $Html.IndexOf('Low example')) 'High precedes Low'
Assert-True ($Html.Contains('&lt;img src=x onerror=alert(1)&gt;')) 'Finding text is HTML encoded'
Assert-True (-not $Html.Contains('<script>alert(1)</script>')) 'Evidence cannot inject scripts'
Assert-True ($Html.Contains('&lt;script&gt;literal&lt;/script&gt;')) 'Command text is HTML encoded'
Assert-True ($Html.Contains('<details class="report-section" id="findings" open>')) 'Findings open by default'
Assert-True ($Html.Contains('<button type="button">How to exploit</button>')) 'Exploitation column has sortable header'
Assert-True ($Html.Contains('<button type="button">Next verification steps</button>')) 'Verification column has sortable header'
Assert-True ($Html.Contains('Copy steps')) 'Verification commands can be copied'
Assert-True (-not $Html.Contains('<script>alert(3)</script>')) 'Verification commands cannot inject HTML'
Assert-True ($Html.Contains('&lt;script&gt;alert(3)&lt;/script&gt;')) 'Verification commands remain readable after encoding'
$FirstFindingRow=[regex]::Match($Html,'<tbody><tr[^>]*>(.*?)</tr>',[Text.RegularExpressions.RegexOptions]::Singleline).Groups[1].Value
Assert-True ([regex]::Matches($FirstFindingRow,'<td\b').Count -eq 9) 'Finding rows contain nine cells'
Assert-True ($Html.Contains('&lt;img src=x onerror=alert(2)&gt;')) 'Exploitation text is HTML encoded'
Assert-True (-not $Html.Contains('<img src=x onerror=alert(2)>')) 'Exploitation context cannot inject HTML'
$Sample.Findings=@($FixtureFinding)
$FullHtml=New-AssessmentHtml $Sample
Assert-True ($FullHtml.Contains('END-OF-LONG-EVIDENCE')) 'Complete long evidence reaches HTML'
Assert-True ($FullHtml.Contains('Full evidence row 20')) 'All evidence records reach HTML'
$FullText=New-AssessmentText $Sample
Assert-True ($FullText.Contains('END-OF-LONG-EVIDENCE')) 'Complete long evidence reaches TXT'
Assert-True ($FullText.Contains('HowToExploit')) 'TXT includes exploitation context'
Assert-True ($FullText.Contains('VerificationSteps')) 'TXT includes verification field'
$null=ConvertTo-ReportValueHtml @($null)
$Sample.Findings=@()
$EmptyHtml=New-AssessmentHtml $Sample
Assert-True ($EmptyHtml.Contains('Security findings (0)')) 'Empty findings report renders'
$Sample.Findings=$Findings
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$Html | Set-Content -LiteralPath (Join-Path $OutputDirectory 'sample-report.html') -Encoding UTF8
$EmptyHtml | Set-Content -LiteralPath (Join-Path $OutputDirectory 'empty-report.html') -Encoding UTF8
$Sample | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'sample-report.json') -Encoding UTF8

# Exercise the actual report-writing tail against synthetic collector variables.
$ComputerName='SYNTHETIC-HOST'; $StartTime=Get-Date; $IsAdmin=$false
$SeveritySummary=$Sample.SeveritySummary; $AdditionalChecks=$Sample.AdditionalChecks
$TimeoutSeconds=30; $RunVerification=$false
$OS=$Sample.System.OperatingSystem; $Errors=$Sample.CollectionErrors
$JsonFile=Join-Path $OutputDirectory 'integration-report.json'
$TxtFile=Join-Path $OutputDirectory 'integration-report.txt'
$HtmlFile=Join-Path $OutputDirectory 'integration-report.html'
$HashFile=Join-Path $OutputDirectory 'integration-report_SHA256.txt'
$ReportStart=$Source.IndexOf('$Report = [ordered]@{')
$ReportCode=$Source.Substring($ReportStart).Replace('[Security.Principal.WindowsIdentity]::GetCurrent().Name', "'EXAMPLE\Reviewer'")
& ([scriptblock]::Create($ReportCode)) 6>$null
foreach ($File in @($JsonFile,$TxtFile,$HtmlFile,$HashFile)) {
    Assert-True ((Get-Item -LiteralPath $File).Length -gt 0) "Report artifact generated: $File"
}
$RoundTrip=Get-Content -LiteralPath $JsonFile -Raw | ConvertFrom-Json
Assert-True ($RoundTrip.Findings.Count -eq $Findings.Count) 'JSON preserves finding count'
Assert-True (-not [string]::IsNullOrWhiteSpace($RoundTrip.Findings[0].HowToExploit)) 'JSON retains exploitation context'
Assert-True ($null -ne $RoundTrip.Findings[0].PSObject.Properties['VerificationSteps']) 'JSON retains verification field'
Assert-True ($RoundTrip.AdditionalChecks.Count -eq 1) 'JSON contains additional checks'
Assert-True ((Get-Content -LiteralPath $TxtFile -Raw).Contains('Get-ItemProperty')) 'TXT includes commands'
foreach ($File in @($JsonFile,$TxtFile,$HtmlFile)) {
    Assert-True ((Get-Content -LiteralPath $HashFile -Raw).Contains((Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash)) 'SHA256 manifest matches report'
}
Write-Host "PASS: $script:Assertions assertions on PowerShell $($PSVersionTable.PSVersion). Synthetic reports: $OutputDirectory"
