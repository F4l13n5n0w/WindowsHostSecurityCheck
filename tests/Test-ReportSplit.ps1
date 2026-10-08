#Requires -Version 5.1
param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'artifacts\report-split'))
$ErrorActionPreference='Stop'
$SourcePath=Join-Path (Split-Path $PSScriptRoot -Parent) 'windows_security_check_v3.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($SourcePath,[ref]$tokens,[ref]$errors)
if ($errors.Count) {throw ($errors | Out-String)}
foreach ($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {. ([scriptblock]::Create($definition.Extent.Text))}
$script:Assertions=0
function Assert-True([bool]$Condition,[string]$Message) {$script:Assertions++;if(-not $Condition){throw "FAILED: $Message"}}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$Findings=@([pscustomobject]@{Severity='Low';Category='Host';Finding='Host fixture';Status='Review';Command='Get-Date';EvidenceData=@{Value='host-data'};Evidence='host-data';EvidenceSummary='Host observation';Recommendation='Review';HowToExploit='Requires context'})
for ($i=0;$i -lt 101;$i++) {
    $Findings += [pscustomobject]@{
        Severity=$(if($i -eq 100){'High'}else{'Medium'});Category='DLL Security';Finding=('Installed software DLL loading candidate: fixture '+$i)
        Status='Review';Command='Get-Date';EvidenceData=@{BinaryPath="C:\fixture\app.exe";DllPath="C:\fixture\plugin.dll";Saved='DLL-ONLY-SENTINEL';Record=$i}
        Evidence='DLL-ONLY-SENTINEL';EvidenceSummary='DLL candidate';Recommendation='Check loading';HowToExploit='Requires loading and write access'
        VerificationResult=[pscustomobject]@{Status='Saved';Explanation='Historical verification';Steps=@()}
    }
}
$Imports=@(1..26 | ForEach-Object {[pscustomobject]@{BinaryPath=('C:\fixture\binary'+$_+'.exe');Imports=@('custom.dll');Record=$_}})
$App=[pscustomobject]@{Software='Fixture <script> & app';Status='Partial';Explanation='Coverage incomplete';BinaryImports=$Imports;DllCandidates=@([pscustomobject]@{DllName='DLL-ONLY-SENTINEL'});ProcessAccessChecks=@();RegisteredConsumers=@();Errors=@('Saved error')}
$Findings[-1].VerificationResult.Steps=@([pscustomobject]@{Name='Saved timestamp';Status='Completed';StartedAt=[datetime]'2026-10-08T10:00:00';DurationMilliseconds=42;Explanation='Historical result';Command='Get-Date';Output='SAVED-FULL-OUTPUT';Errors=@();Warnings=@();Information=@()})
$ReportData=[ordered]@{Metadata=[ordered]@{Host=$env:COMPUTERNAME;Version='3.1'};Findings=$Findings;SeveritySummary=(Get-AssessmentSeveritySummary $Findings);CollectionErrors=@('host-error');SoftwareDllAssessment=[ordered]@{Overview=@{ApplicationsInventoried=1;IncompleteApplications=1};KnownDllNames=@('kernel32.dll');Applications=@($App)}}
$InputFile=Join-Path $OutputDirectory 'source.json'
$ReportData | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $InputFile -Encoding UTF8
$Before=(Get-FileHash -LiteralPath $InputFile).Hash
$Destination=Join-Path $OutputDirectory 'split'
Update-AssessmentReport $InputFile $Destination 6>$null
$HostJson=Get-Content -LiteralPath (Join-Path $Destination 'source.json') -Raw | ConvertFrom-Json
$DllJson=Get-Content -LiteralPath (Join-Path $Destination 'source_DllAnalysis.json') -Raw | ConvertFrom-Json
$HostHtml=Get-Content -LiteralPath (Join-Path $Destination 'source.html') -Raw
$DllHtml=Get-Content -LiteralPath (Join-Path $Destination 'source_DllAnalysis.html') -Raw
Assert-True ($HostJson.Findings.Count -eq 1 -and $HostJson.SeveritySummary.Total -eq 1) 'Host findings and severity counts exclude DLL findings'
Assert-True ($null -eq $HostJson.SoftwareDllAssessment -and -not $HostHtml.Contains('DLL-ONLY-SENTINEL')) 'Host HTML and JSON do not contain DLL evidence'
Assert-True ($HostHtml.Contains('href="source_DllAnalysis.html"')) 'Host links the separate DLL index'
Assert-True ($DllJson.Findings.Count -eq 101 -and $DllJson.SeveritySummary.High -eq 1 -and $DllJson.SeveritySummary.Total -eq 101) 'DLL findings retain their own exact counts'
Assert-True ($DllJson.SoftwareDllAssessment.Applications[0].BinaryImports.Count -eq 26 -and $DllJson.Findings[0].EvidenceData.Saved -eq 'DLL-ONLY-SENTINEL') 'Full exports preserve all nested evidence'
Assert-True ($DllJson.Findings[0].VerificationResult.Explanation -eq 'Historical verification') 'Saved verification remains with its finding'
Assert-True ($DllJson.Metadata.ReportKind -eq 'DllAnalysis' -and $HostJson.Metadata.ReportKind -eq 'HostAssessment') 'Partitions identify report kind'
Assert-True ((Get-FileHash -LiteralPath $InputFile).Hash -eq $Before) 'Refresh preserves the original source'
Assert-True ($DllHtml.Length -lt 20000 -and -not $DllHtml.Contains('DLL-ONLY-SENTINEL')) 'DLL index does not embed finding commands or full evidence'
$Details=Join-Path $Destination 'source_DllAnalysis_Details'
$ListOne=Get-Content -LiteralPath (Join-Path $Details 'findings-1.html') -Raw
$ListTwo=Get-Content -LiteralPath (Join-Path $Details 'findings-2.html') -Raw
Assert-True (([regex]::Matches($ListOne,'<tr data-rank=')).Count -eq 100 -and ([regex]::Matches($ListTwo,'<tr data-rank=')).Count -eq 1) 'Finding lists paginate at 100 rows without dropping the last row'
Assert-True ($ListOne.Contains('fixture 100') -and $ListOne.IndexOf('fixture 100') -lt $ListOne.IndexOf('fixture 0')) 'High severity starts the first page before medium findings'
$Detail=Get-Content -LiteralPath (Join-Path $Details 'finding-000001.html') -Raw
Assert-True ($Detail.Contains('DLL-ONLY-SENTINEL') -and $Detail.Contains('Next verification steps') -and $Detail.Contains('issue-highlight')) 'Finding detail retains full evidence, commands and highlight rendering'
Assert-True ($Detail.Contains('SAVED-FULL-OUTPUT') -and $Detail.Contains('42 ms')) 'Imported verification timestamps render as text on both PowerShell versions'
$AppFirst=Get-Content -LiteralPath (Join-Path $Details 'application-000001-BinaryImports-1.html') -Raw
$AppLast=Get-Content -LiteralPath (Join-Path $Details 'application-000001-BinaryImports-2.html') -Raw
Assert-True ($AppFirst.Contains('binary25.exe') -and -not $AppFirst.Contains('binary26.exe') -and $AppLast.Contains('binary26.exe')) 'Application binary evidence is split at 25 records'
Assert-True (-not $AppFirst.Contains('DLL-ONLY-SENTINEL')) 'Binary detail pages do not duplicate other candidate arrays'
Assert-True ($AppFirst.Contains('&lt;script&gt;') -and -not $AppFirst.Contains('Fixture <script>')) 'Application names are HTML encoded'
foreach ($ManifestName in @('source_SHA256.txt','source_DllAnalysis_SHA256.txt')) {
    $Manifest=Get-Content -LiteralPath (Join-Path $Destination $ManifestName)
    foreach ($Line in $Manifest) {
        $Parts=$Line -split '  ',2
        Assert-True ((Get-FileHash -LiteralPath (Join-Path $Destination $Parts[1])).Hash -eq $Parts[0]) 'Manifest covers a generated artifact including detail pages'
    }
}
# A separate DLL JSON can itself be refreshed; it must not grow another DLL suffix or host report.
$DllRefresh=Join-Path $OutputDirectory 'dll-refresh'
Update-AssessmentReport (Join-Path $Destination 'source_DllAnalysis.json') $DllRefresh 6>$null
Assert-True ((Test-Path -LiteralPath (Join-Path $DllRefresh 'source_DllAnalysis.html')) -and -not (Test-Path -LiteralPath (Join-Path $DllRefresh 'source_DllAnalysis_DllAnalysis.html'))) 'Standalone DLL refresh keeps its report kind and name'
# Verification is routed to both partitions, with execution results staying in their partition.
& {
    $script:VerifiedCount=0
    function Update-AssessmentVerification {param($Assessment,[switch]$RunVerification,[int]$TimeoutSeconds) if ($RunVerification) {$script:VerifiedCount+=@($Assessment.Findings).Count;foreach ($Finding in $Assessment.Findings) {Set-ReportProperty $Finding 'VerificationResult' ([pscustomobject]@{Status='TestExecuted';Steps=@()})}}}
    $Copy=Get-Content -LiteralPath $InputFile -Raw | ConvertFrom-Json
    Export-AssessmentReports (ConvertTo-AssessmentDictionary $Copy) (Join-Path $OutputDirectory 'verified') 'verified' -RunVerification 6>$null
    $Saved=Get-Content -LiteralPath (Join-Path $OutputDirectory 'verified\verified_DllAnalysis.json') -Raw | ConvertFrom-Json
    Assert-True ($script:VerifiedCount -eq 102 -and $Saved.Findings[0].VerificationResult.Status -eq 'TestExecuted') 'Optional verification includes host and DLL findings before export'
}
$Empty=[ordered]@{Metadata=@{Host='Synthetic'};Findings=@();SoftwareDllAssessment=@{Overview=@{Skipped=$true};Applications=@()}}
$EmptyDir=Join-Path $OutputDirectory 'empty'
Export-AssessmentReports $Empty $EmptyDir 'empty' 6>$null
Assert-True ((Test-Path -LiteralPath (Join-Path $EmptyDir 'empty_DllAnalysis.html')) -and $Empty.SeveritySummary.Total -eq 0) 'Empty and skipped DLL scans still have a separate coverage report'
Write-Host "PASS: $script:Assertions report split assertions on PowerShell $($PSVersionTable.PSVersion). Artifacts: $OutputDirectory"
