#Requires -Version 5.1
<#
.SYNOPSIS
Adds next-step commands to an existing assessment without running host collectors.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$InputJson,
    [string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$SourcePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'windows_security_check_v2.ps1'
$Tokens = $null; $ParseErrors = $null
$Ast = [System.Management.Automation.Language.Parser]::ParseFile($SourcePath, [ref]$Tokens, [ref]$ParseErrors)
if ($ParseErrors.Count) { throw ($ParseErrors | Out-String) }
# Load function definitions only; dot-sourcing the assessment would run collectors.
foreach ($Definition in $Ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)) {
    . ([scriptblock]::Create($Definition.Extent.Text))
}
$InputPath = (Resolve-Path -LiteralPath $InputJson -ErrorAction Stop).Path
$InputObject = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
if ($null -eq $InputObject.Metadata -or $null -eq $InputObject.Findings) {
    throw 'Input is not an assessment report with Metadata and Findings.'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path (Split-Path $InputPath -Parent) 'with_verification'
}
$OutputPath = [IO.Path]::GetFullPath($OutputDirectory)
$BaseName = [IO.Path]::GetFileNameWithoutExtension($InputPath)
$Files = @('json','txt','html') | ForEach-Object { Join-Path $OutputPath ($BaseName + '.' + $_) }
if ($Files[0] -eq $InputPath) { throw 'Output must be separate from the original report.' }
$InputObject.Metadata | Add-Member NoteProperty VerificationStepsAddedAt ((Get-Date).ToString('o')) -Force
$InputObject.Metadata | Add-Member NoteProperty VerificationRendererVersion '2.3' -Force
$InputObject.Metadata | Add-Member NoteProperty SourceReport ([IO.Path]::GetFileName($InputPath)) -Force
foreach ($Finding in @($InputObject.Findings)) {
    $Steps = Get-FindingVerificationSteps -Title $Finding.Finding -Category $Finding.Category -EvidenceData $Finding.EvidenceData -Command $Finding.Command
    $Finding | Add-Member NoteProperty VerificationSteps $Steps -Force
}
$Report = [ordered]@{}
foreach ($Property in $InputObject.PSObject.Properties) { $Report[$Property.Name] = $Property.Value }
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
ConvertTo-Json -InputObject $Report -Depth 100 -WarningAction Stop | Set-Content -LiteralPath $Files[0] -Encoding UTF8
New-AssessmentText $Report | Set-Content -LiteralPath $Files[1] -Encoding UTF8
New-AssessmentHtml $Report | Set-Content -LiteralPath $Files[2] -Encoding UTF8
$Hashes = foreach ($File in $Files) {
    $Hash = Get-FileHash -LiteralPath $File -Algorithm SHA256
    '{0}  {1}' -f $Hash.Hash, [IO.Path]::GetFileName($File)
}
$Hashes | Set-Content -LiteralPath (Join-Path $OutputPath ($BaseName + '_SHA256.txt')) -Encoding UTF8
Write-Host "Updated report: $($Files[2])"
Write-Host 'Source scan metadata, evidence, finding counts and collection results are preserved. No host scan was performed.'
