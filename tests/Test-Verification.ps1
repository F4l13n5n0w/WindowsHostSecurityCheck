#Requires -Version 5.1
param(
    [string]$ProjectRoot=(Split-Path $PSScriptRoot -Parent),
    [string]$OutputDirectory=(Join-Path $PSScriptRoot 'artifacts\verification')
)
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$SourcePath=Join-Path $ProjectRoot 'windows_security_check_v3.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) {throw ($parseErrors | Out-String)}
foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {. ([scriptblock]::Create($definition.Extent.Text))}
$script:Assertions=0
function Assert-True([bool]$Condition,[string]$Message) {
    $script:Assertions++
    if (-not $Condition) {throw "FAILED: $Message"}
}
function Assert-Parses([string]$Code) {
    $t=$null;$e=$null
    $null=[Management.Automation.Language.Parser]::ParseInput($Code,[ref]$t,[ref]$e)
    Assert-True ($e.Count -eq 0) 'Generated command parses'
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$marker=Join-Path $OutputDirectory 'must-not-execute.txt'
$evil='Set-Content -LiteralPath '+(ConvertTo-PowerShellLiteral $marker)+" -Value 'bad'"
$unknown=[pscustomobject]@{Finding='Unknown future finding';Command=$evil;VerificationSteps=$evil;EvidenceData=$null}
Assert-True (@(Get-LocalVerificationPlan $unknown).Count -eq 0) 'Unknown command text is never used as an execution plan'
Assert-True ((Invoke-FindingVerification $unknown).Status -eq 'NotApplicable') 'Unsupported finding is explicit'
Assert-True (-not (Test-Path -LiteralPath $marker)) 'Report-supplied commands did not execute'
$update=[pscustomobject]@{Finding='Windows Update Agent reports missing software updates'}
Assert-True ((Invoke-FindingVerification $update).Explanation -match 'contact an update service') 'Online update search exclusion is explained'

$file=Join-Path $OutputDirectory "file with ' quote.txt"
[IO.File]::WriteAllText($file,('original bytes '+('x'*8000)))
$data=[pscustomobject]@{TaskName="Task 'quoted";TaskPath="\Folder 'quoted\";TaskFile=$file;Action=$file;Name="Service 'quoted";Executable=$file;Directory=$OutputDirectory;RegistryPath='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run';Path=$OutputDirectory;BinaryPath=$file;DllPath=(Join-Path $OutputDirectory 'fixture.dll');ProcessId=$PID}
$titles=@('Scheduled task definition is broadly writable: fixture','Scheduled task executable is broadly writable: fixture','Scheduled task executable directory is broadly writable: fixture','Service executable is writable by a broad principal: fixture','Service executable directory is writable by a broad principal: fixture','Service registry configuration is writable by a broad principal: fixture','Potentially broad service-object permissions: fixture','Unquoted service executable path: fixture','Autorun executable is broadly writable: fixture','Autorun executable directory is broadly writable: fixture','Startup folder has broad write permissions: fixture','System PATH directory is broadly writable','AlwaysInstallElevated is enabled','Sensitive user right configured: fixture','Safe DLL search mode is disabled','Image File Execution Options debugger redirects are configured')
foreach ($title in $titles) {
    $finding=[pscustomobject]@{Finding=$title;EvidenceData=$data;Command=$evil}
    $plan=@(Get-LocalVerificationPlan $finding)
    Assert-True ($plan.Count -gt 0) "$title supported"
    foreach ($step in $plan) {Assert-Parses $step.Command;Assert-True ($step.Command -notmatch 'must-not-execute') 'Plan ignores report command text'}
}
# Check the maintained finding titles all have a plan, except online update searches.
$calls=$ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Finding'},$true)
foreach ($call in $calls) {
    $titleExpression=$call.CommandElements[3]
    if ($titleExpression -is [Management.Automation.Language.StringConstantExpressionAst]) {$title=$titleExpression.Value}
    else {$title=$titleExpression.Extent.Text.Trim('"')}
    if ($title -match '^Windows Update Agent') {continue}
    $plan=@(Get-LocalVerificationPlan ([pscustomobject]@{Finding=$title;EvidenceData=$data;Command=$evil}))
    Assert-True ($plan.Count -gt 0) "Maintained title supported: $title"
    foreach ($step in $plan) {Assert-Parses $step.Command}
}
foreach ($badPath in @('\\server\share\file','relative.txt','\\?\C:\file')) {
    $blocked=$false
    try {Assert-LocalVerificationPath $badPath 'File'} catch {$blocked=$true}
    Assert-True $blocked 'Remote/device/relative path rejected'
}
$badFinding=[pscustomobject]@{Finding='Autorun executable is broadly writable: fixture';EvidenceData=[pscustomobject]@{RegistryPath='HKLM:\SECURITY';Executable=$file}}
Assert-True ((Invoke-FindingVerification $badFinding).Status -eq 'Unavailable') 'Unexpected registry root rejected'
$badFinding=[pscustomobject]@{Finding='Scheduled task definition is broadly writable: fixture';EvidenceData=[pscustomobject]@{TaskName='missing'}}
Assert-True ((Invoke-FindingVerification $badFinding).Status -eq 'Unavailable') 'Incomplete saved identity is not verified'

$long=('0123456789'*1600)+'<script>alert("unsafe")</script>'
$step=New-VerificationStep 'Synthetic capture' ("Write-Output "+(ConvertTo-PowerShellLiteral $long)+"`nWrite-Warning 'warning preserved'`nWrite-Information 'information preserved' -InformationAction Continue`nWrite-Verbose 'verbose preserved' -Verbose`nWrite-Debug 'debug preserved' -Debug`nWrite-Error 'synthetic failure'`nWrite-Output 'after error'") 'Synthetic explanation'
$result=Invoke-VerificationStep $step 5
Assert-True ($result.Status -eq 'Error') 'Nonterminating error is recorded as error'
Assert-True ($result.OutputData[0] -eq $long -and $result.OutputData[-1] -eq 'after error') 'Complete long and subsequent output preserved'
Assert-True ($result.Errors.Count -eq 1 -and $result.Errors[0].Message -eq 'synthetic failure') 'Error record retained'
Assert-True ($result.Warnings[0] -eq 'warning preserved') 'Warning stream retained'
Assert-True ($result.Information.Count -gt 0 -and $result.Verbose.Count -gt 0 -and $result.Debug.Count -gt 0) 'Information/verbose/debug streams retained'
$terminating=Invoke-VerificationStep (New-VerificationStep 'Terminating' "Write-Output 'before throw'; throw 'stop now'" 'Terminating check') 5
Assert-True ($terminating.Status -eq 'Error' -and $terminating.OutputData[0] -eq 'before throw') 'Output preceding terminating error retained'
$timed=Invoke-VerificationStep (New-VerificationStep 'Timeout' "Write-Output 'partial'; Start-Sleep -Seconds 10" 'Timeout check') 1
Assert-True ($timed.Status -eq 'TimedOut' -and $timed.OutputData[0] -eq 'partial') 'Timeout preserves partial output'
Assert-True ($timed.Explanation -match 'partial' -and $timed.DurationMilliseconds -lt 7000) 'Timeout explained and bounded in synthetic test'
$empty=Invoke-VerificationStep (New-VerificationStep 'Empty' '$null' 'Empty check') 5
Assert-True ($empty.Explanation -match 'not automatically a pass') 'Empty output is not a pass'
$before=(Get-FileHash -LiteralPath $file).Hash
$plan=@(Get-LocalVerificationPlan ([pscustomobject]@{Finding=$titles[0];EvidenceData=$data}))
$probeStep=$plan | Where-Object Name -eq 'Existing-file write-open probe'
$probe=Invoke-VerificationStep $probeStep 5
Assert-True ($probe.OutputData[0].WriteOpenSucceeded -and $probe.OutputData[0].BytesWritten -eq 0) 'Probe confirms access without writing'
Assert-True ((Get-FileHash -LiteralPath $file).Hash -eq $before) 'Probe leaves fixture contents unchanged'
[IO.File]::Delete($file)
$missing=Invoke-VerificationStep $probeStep 5
Assert-True (-not $missing.OutputData[0].WriteOpenSucceeded -and $missing.OutputData[0].FailureKind -eq 'NotFound') 'Missing file distinguished from denied access'
Assert-True (-not (Test-Path -LiteralPath $file)) 'Probe does not create missing file'
$html=ConvertTo-VerificationResultHtml ([pscustomobject]@{Status='Partial';Explanation='Synthetic';Steps=@($result,$probe)}) $titles[0]
Assert-True ($html.Contains([Net.WebUtility]::HtmlEncode($long))) 'HTML retains full escaped response'
Assert-True (-not $html.Contains('<script>alert')) 'HTML injection escaped'
Assert-True ($html -match 'issue-highlight.*WriteOpenSucceeded') 'Write-open success highlighted'
Assert-True ($html -match 'synthetic failure' -and $html -match 'Executed command') 'HTML includes command and errors'
$aclOutput=@{Rules=@([ordered]@{Identity='Administrators';BroadWriteAllow=$false;Rights='FullControl';AccessControlType='Allow'},[ordered]@{Identity='Users';BroadWriteAllow=$true;Rights='Modify';AccessControlType='Allow'},[ordered]@{Identity='Users';BroadWriteAllow=$false;Rights='Write';AccessControlType='Deny'})}
$aclHtml=ConvertTo-VerificationResultHtml ([pscustomobject]@{Status='ChecksCompleted';Steps=@([pscustomobject]@{Name='ACL fixture';Output=(Convert-ToSafeString $aclOutput)})}) $titles[0]
Assert-True ($aclHtml -notmatch 'issue-highlight[^>]*>[^\r\n]*FullControl' -and $aclHtml -notmatch 'issue-highlight[^>]*>[^\r\n]*&quot;Write&quot;') 'Admin and deny ACE rights are not highlighted as broad allow issues'
Assert-True ($aclHtml -match 'issue-highlight[^>]*>[^\r\n]*Modify') 'Broad write allow ACE rights highlighted'
$html | Set-Content -LiteralPath (Join-Path $OutputDirectory 'verification-transcripts.html') -Encoding UTF8

# End-to-end single-file test: replace one query with fixed synthetic output.
$fixtureRoot=Join-Path $OutputDirectory 'standalone-fixture'
New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
$fixtureSource=Get-Content -LiteralPath $SourcePath -Raw
$queryFunction=$ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-ConfigurationVerificationPlan'},$true)[0]
$syntheticQuery="function Get-ConfigurationVerificationPlan { param([string]`$Title); New-VerificationStep 'Synthetic integration query' " + (ConvertTo-PowerShellLiteral ('Write-Output '+(ConvertTo-PowerShellLiteral $long))) + " 'Complete synthetic response' }"
$fixtureSource=$fixtureSource.Replace($queryFunction.Extent.Text,$syntheticQuery)
$helper=Join-Path $fixtureRoot 'windows_security_check_v3.ps1'
$fixtureSource | Set-Content -LiteralPath $helper -Encoding UTF8
Assert-True (-not (Test-Path -LiteralPath (Join-Path $fixtureRoot 'tools'))) 'Standalone fixture has no helper folder'
$inputFile=Join-Path $fixtureRoot 'input.json'
$report=[ordered]@{Metadata=[ordered]@{Host=$env:COMPUTERNAME;Version='2.3';AssessmentStarted='historical'};SeveritySummary=[ordered]@{Critical=0;High=1;Medium=0;Low=0;Informational=0};Findings=@([pscustomobject]@{Severity='High';Category='Synthetic';Finding='Synthetic finding';Status='Review';EvidenceSummary='historical evidence';EvidenceData=@{Value='historical'};Evidence='historical evidence';Command=$evil;VerificationSteps=$evil;HowToExploit='conditional';Recommendation='review'});CollectionErrors=@('historical error')}
$report | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $inputFile -Encoding UTF8
$sourceHash=(Get-FileHash -LiteralPath $inputFile).Hash
& $helper -InputJson $inputFile -OutputDirectory (Join-Path $fixtureRoot 'commands-only')
$commands=Get-Content -LiteralPath (Join-Path $fixtureRoot 'commands-only\input.json') -Raw | ConvertFrom-Json
Assert-True ($null -eq $commands.Findings[0].VerificationResult) 'Default mode does not execute'
& $helper -InputJson $inputFile -OutputDirectory (Join-Path $fixtureRoot 'executed') -RunVerification -TimeoutSeconds 5
$executed=Get-Content -LiteralPath (Join-Path $fixtureRoot 'executed\input.json') -Raw | ConvertFrom-Json
Assert-True ($executed.Findings[0].VerificationResult.Steps[0].OutputData[0] -eq $long) 'End-to-end JSON retains actual complete output'
Assert-True ($executed.Metadata.VerificationExecution.Host -eq $env:COMPUTERNAME) 'Execution host recorded'
Assert-True ($executed.Findings[0].Evidence -eq 'historical evidence' -and $executed.CollectionErrors[0] -eq 'historical error') 'Historical evidence and errors preserved'
Assert-True ((Get-FileHash -LiteralPath $inputFile).Hash -eq $sourceHash) 'Input JSON unchanged'
Assert-True (-not (Test-Path -LiteralPath $marker)) 'Injected input command never executed end-to-end'
foreach ($extension in @('html','txt')) {
    $text=Get-Content -LiteralPath (Join-Path $fixtureRoot ('executed\input.'+$extension)) -Raw
    Assert-True ($text -match 'Synthetic integration query' -and $text.Contains('0123456789'*1600)) "$extension retains full executed output"
}
Assert-True ((Get-Content -LiteralPath (Join-Path $fixtureRoot 'executed\input_SHA256.txt')).Count -eq 3) 'Manifest includes all artifacts'
Assert-True ($executed.Metadata.VerificationExecution.EngineVersion -eq '3.1' -and $executed.Metadata.Version -eq '2.3') 'Verification version updated while historical scan version preserved'
& $helper -InputJson $inputFile
Assert-True (Test-Path -LiteralPath (Join-Path $fixtureRoot 'with_verification\input.html')) 'Default refresh output is beside the input'
$blocked=$false
try {& $helper -InputJson $inputFile -OutputDirectory $fixtureRoot -RunVerification} catch {$blocked=$_.Exception.Message -match 'separate from the original'}
Assert-True ($blocked -and (Get-FileHash -LiteralPath $inputFile).Hash -eq $sourceHash) 'Input overwrite rejected'
$blocked=$false
try {& $helper -InputJson $inputFile -SkipWindowsUpdateScan} catch {$blocked=$true}
Assert-True $blocked 'Scan-only switch cannot be combined with refresh mode'

# Exercise scan orchestration with synthetic collector data, retaining the actual
# scan initialization, verification hook and report-writing tail from v3.
$collectorStart=$fixtureSource.IndexOf('$IsAdmin = Test-IsAdministrator')
$hookStart=$fixtureSource.IndexOf('# Optional checks run against the just-collected findings')
$fixtureJson=ConvertTo-PowerShellLiteral ($report | ConvertTo-Json -Depth 100 -Compress)
$syntheticScan='$fixture='+$fixtureJson+" | ConvertFrom-Json`n"+@'
$Report=[ordered]@{
    Metadata=[ordered]@{Host=$env:COMPUTERNAME;Version='3.1';AssessmentStarted=$StartTime;AssessmentCompleted=(Get-Date)}
    SeveritySummary=$fixture.SeveritySummary;Findings=@($fixture.Findings);CollectionErrors=@()
}
$SeveritySummary=$Report.SeveritySummary
'@
$scanSource=$fixtureSource.Substring(0,$collectorStart)+$syntheticScan+"`n"+$fixtureSource.Substring($hookStart)
$scanScript=Join-Path $fixtureRoot 'synthetic-scan.ps1'
$scanSource | Set-Content -LiteralPath $scanScript -Encoding UTF8
$scanOnlyDir=Join-Path $fixtureRoot 'scan-only'
& $scanScript -OutputDirectory $scanOnlyDir -SkipWindowsUpdateScan 6>$null
$scanOnlyJson=Get-ChildItem -LiteralPath $scanOnlyDir -Filter '*.json' | Select-Object -First 1
$scanOnly=Get-Content -LiteralPath $scanOnlyJson.FullName -Raw | ConvertFrom-Json
Assert-True ($scanOnly.Metadata.Version -eq '3.1' -and $null -eq $scanOnly.Findings[0].VerificationResult) 'Fresh scan-only mode does not execute verification'
$scanVerifiedDir=Join-Path $fixtureRoot 'scan-verified'
& $scanScript -OutputDirectory $scanVerifiedDir -SkipWindowsUpdateScan -RunVerification -TimeoutSeconds 5 6>$null
$scanVerifiedJson=Get-ChildItem -LiteralPath $scanVerifiedDir -Filter '*.json' | Select-Object -First 1
$scanVerified=Get-Content -LiteralPath $scanVerifiedJson.FullName -Raw | ConvertFrom-Json
Assert-True ($scanVerified.Metadata.VerificationExecution.EngineVersion -eq '3.1') 'Fresh dictionary metadata includes verification session'
Assert-True ($scanVerified.Findings[0].VerificationResult.Steps[0].OutputData[0] -eq $long) 'Fresh scan executes verification before serializing reports'
Assert-True (-not (Test-Path -LiteralPath $marker)) 'Fresh scan does not execute report-provided commands'
$manifest=Get-ChildItem -LiteralPath $scanVerifiedDir -Filter '*_SHA256.txt' | Select-Object -First 1
$manifestText=Get-Content -LiteralPath $manifest.FullName -Raw
foreach ($artifact in Get-ChildItem -LiteralPath $scanVerifiedDir | Where-Object Extension -in @('.json','.html','.txt') | Where-Object Name -notlike '*_SHA256.txt') {
    Assert-True ($manifestText.Contains((Get-FileHash -LiteralPath $artifact.FullName).Hash)) 'Scan hashes include verification output'
}
$report.Metadata.Host='different-host.invalid'
$report | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $inputFile -Encoding UTF8
$blocked=$false
try {& $helper -InputJson $inputFile -OutputDirectory (Join-Path $fixtureRoot 'wrong-host') -RunVerification} catch {$blocked=$_.Exception.Message -match 'original scanned host'}
Assert-True ($blocked -and -not (Test-Path -LiteralPath (Join-Path $fixtureRoot 'wrong-host'))) 'Host mismatch blocks execution before output'
Write-Host "Passed $script:Assertions verification assertions. Artifacts: $OutputDirectory"
