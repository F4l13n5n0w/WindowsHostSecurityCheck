#Requires -Version 5.1
<#
.SYNOPSIS
Adds next-step commands and optionally executes local verification checks.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)] [string]$InputJson,
    [string]$OutputDirectory,
    [switch]$RunVerification,
    [ValidateRange(1,300)] [int]$TimeoutSeconds = 30
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
. (Join-Path $PSScriptRoot 'VerificationRunner.ps1')
$InputPath = (Resolve-Path -LiteralPath $InputJson -ErrorAction Stop).Path
$InputObject = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
if ($null -eq $InputObject.Metadata -or $null -eq $InputObject.Findings) {
    throw 'Input is not an assessment report with Metadata and Findings.'
}
if ($RunVerification -and ([string]::IsNullOrWhiteSpace([string]$InputObject.Metadata.Host) -or
    [string]$InputObject.Metadata.Host -ne $env:COMPUTERNAME)) {
    throw 'RunVerification must run on the original scanned host (Metadata.Host must match COMPUTERNAME).'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path (Split-Path $InputPath -Parent) 'with_verification'
}
$OutputPath = [IO.Path]::GetFullPath($OutputDirectory)
$BaseName = [IO.Path]::GetFileNameWithoutExtension($InputPath)
$Files = @('json','txt','html') | ForEach-Object { Join-Path $OutputPath ($BaseName + '.' + $_) }
if ($Files[0] -eq $InputPath) { throw 'Output must be separate from the original report.' }
$InputObject.Metadata | Add-Member NoteProperty VerificationStepsAddedAt ((Get-Date).ToString('o')) -Force
$InputObject.Metadata | Add-Member NoteProperty VerificationRendererVersion '2.4' -Force
$InputObject.Metadata | Add-Member NoteProperty SourceReport ([IO.Path]::GetFileName($InputPath)) -Force
if ($RunVerification) {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
    $InputObject.Metadata | Add-Member NoteProperty VerificationExecution ([pscustomobject]@{
        Host=$env:COMPUTERNAME; User=$Identity.Name; UserSid=$Identity.User.Value
        IsAdministrator=$Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        PowerShellVersion=[string]$PSVersionTable.PSVersion; StartedAt=(Get-Date).ToString('o')
        CompletedAt=$null; TimeoutSeconds=$TimeoutSeconds; EngineVersion='2.4'
    }) -Force
}
$Index = 0
foreach ($Finding in @($InputObject.Findings)) {
    $Steps = Get-FindingVerificationSteps -Title $Finding.Finding -Category $Finding.Category -EvidenceData $Finding.EvidenceData -Command $Finding.Command
    $Finding | Add-Member NoteProperty VerificationSteps $Steps -Force
    if ($RunVerification) {
        $Index++
        Write-Progress -Activity 'Verifying report findings locally' -Status $Finding.Finding -PercentComplete (100*$Index/[Math]::Max(1,@($InputObject.Findings).Count))
        $Result = Invoke-FindingVerification -Finding $Finding -TimeoutSeconds $TimeoutSeconds
        $Result | Add-Member NoteProperty ExecutionContext ([pscustomobject]@{
            Host=$InputObject.Metadata.VerificationExecution.Host
            User=$InputObject.Metadata.VerificationExecution.User
            UserSid=$InputObject.Metadata.VerificationExecution.UserSid
            IsAdministrator=$InputObject.Metadata.VerificationExecution.IsAdministrator
        }) -Force
        $Finding | Add-Member NoteProperty VerificationResult $Result -Force
        # Display precisely the commands executed, rather than the older suggested transcript.
        if ($Result.Steps.Count) {
            $Finding.VerificationSteps = (@($Result.Steps | ForEach-Object { '# '+$_.Name+"`n"+$_.Command }) -join "`n`n")
        }
    }
}
if ($RunVerification) {
    Write-Progress -Activity 'Verifying report findings locally' -Completed
    $InputObject.Metadata.VerificationExecution.CompletedAt = (Get-Date).ToString('o')
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
Write-Host 'Source scan evidence, finding counts and collection results are preserved.'
if ($RunVerification) { Write-Host 'Fresh verification transcripts and explanations are included. Check errors and caller identity before interpreting results.' }
else { Write-Host 'No verification commands were executed during this refresh. Use -RunVerification to collect fresh results.' }
