#Requires -Version 5.1
param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'artifacts\tls-text'))
$ErrorActionPreference='Stop'
$Source=Join-Path (Split-Path $PSScriptRoot -Parent) 'testssl.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($definition.Extent.Text))}
$script:Assertions=0
function Assert-True([bool]$Condition,[string]$Message){$script:Assertions++;if(-not $Condition){throw "FAILED: $Message"}}
$Catalog=@(Get-TlsCipherCatalog)
$Cbc=$Catalog | Where-Object Id -eq 0xC013
$Anonymous=$Catalog | Where-Object Id -eq 0x001B
$Long='LONG-EVIDENCE-'+('x'*5000)+'-END-EVIDENCE'
$Report=[ordered]@{
    Metadata=[ordered]@{Version='1.0';PowerShellVersion='fixture';CipherCatalogCount=46;AddressScope='one IP per invocation';Target=[pscustomobject]@{Host='fixture.example';ServerName='fixture.example';ConnectAddress='192.0.2.20';ResolvedAddresses=@('192.0.2.20','192.0.2.21');Port=8443;PathAndQuery='/test'};StartedUtc='2026-10-09T00:00:00Z';CompletedUtc='2026-10-09T00:00:02Z';StartTls='none';ChecksRequested=@('Protocols','Ciphers','Http');DeadlineReached=$false;RevocationRequested=$false}
    Protocols=@(
        [pscustomobject]@{Version=2;Protocol='SSLv2';Selected=$false;Status='NotTested';Probe=@{Error='deadline reached'}}
        [pscustomobject]@{Version=768;Protocol='SSLv3';Selected=$false;Status='AlertReceived';Probe=@{Alerts=@('level=2, description=70')}}
        [pscustomobject]@{Version=769;Protocol='TLS 1.0';Selected=$true;Status='ServerHelloObserved';Probe=@{SessionIdLength=0}}
        [pscustomobject]@{Version=771;Protocol='TLS 1.2';Selected=$true;Status='ServerHelloObserved';Probe=@{SessionIdLength=32}}
        [pscustomobject]@{Version=772;Protocol='TLS 1.3';Selected=$true;Status='HelloRetryRequestObserved';Probe=@{SessionIdLength=32}}
    )
    Ciphers=@([pscustomobject]@{Selected=$true;Status='ServerHelloObserved';ProtocolVersion=769;Cipher=$Cbc},[pscustomobject]@{Selected=$true;Status='ServerHelloObserved';ProtocolVersion=771;Cipher=$Anonymous})
    Preference=@([pscustomobject]@{ProtocolVersion=771;Status='ServerPreferenceObservedForPair';Explanation='two reversed offers';Probes=@([pscustomobject]@{SelectedCipher=0x001B;Outcome='ServerHelloObserved'})})
    Extensions=@([pscustomobject]@{Protocol='TLS 1.0';Compression=0;SecureRenegotiationExtensionPresent=$true;Extensions=@([pscustomobject]@{Id=65281;Name='renegotiation_info';Hex='00'})})
    Certificate=$null;NativeSession=$null
    Http=[pscustomobject]@{IsHttp=$true;Incomplete=$true;StatusLine='HTTP/1.1 200 OK';Hsts='';ContentEncoding='gzip';Headers=@([pscustomobject]@{Name='Server';Value='fixture-server'},[pscustomobject]@{Name='X-Frame-Options';Value='SAMEORIGIN'});Cookies=@([pscustomobject]@{Secure=$true;HttpOnly=$false;Raw='fixture=1'})}
    Findings=@([pscustomobject]@{Severity='Low';Finding='Low finding';Status='Review';Explanation='contextual';Recommendation='Review';Command='Get-Date';Evidence=@{Full=$Long}},[pscustomobject]@{Severity='High';Finding='High finding';Status='Observed';Explanation='observed';Recommendation='Review';Command='Get-Date';Evidence=@{Full='saved'}})
    SeveritySummary=@{Critical=0;High=1;Medium=0;Low=1;Informational=0}
    Coverage=@(Get-TlsCoverage);Errors=@([pscustomobject]@{Check='fixture';Status='Inconclusive';Error='fixture-error'})
}
$Json=ConvertTo-Json -InputObject $Report -Depth 40 -WarningAction Stop
$Text=New-TlsReportText $Report $Json
$Headings=@('Testing protocols','Testing cipher categories',"Testing server's cipher preferences",'Testing robust forward secrecy','Testing server defaults','Server Certificate #1','Testing HTTP header response','Testing vulnerabilities','Running client simulations','Rating (experimental)','Full selected evidence')
$Position=-1
foreach($Heading in $Headings){$Next=$Text.IndexOf($Heading);Assert-True ($Next -gt $Position) ('Template section exists in order: '+$Heading);$Position=$Next}
Assert-True ($Text.StartsWith('#'*69) -and $Text.Contains('testssl.ps1 version 1.0')) 'Banner identifies the actual native scanner'
Assert-True ($Text.Contains('Start 2026-10-09 00:00:00 UTC') -and $Text.Contains('Done 2026-10-09 00:00:02 UTC [ 2.0s ]')) 'Start/end footer uses unambiguous UTC and duration'
Assert-True ($Text.Contains('192.0.2.21 (not scanned)')) 'Other IPs are not misreported as scanned'
Assert-True (-not $Text.Contains('www.levelblue.com') -and -not $Text.Contains('199.60.103.2') -and -not $Text.Contains('Using OpenSSL')) 'Template host and engine results are not reused'
Assert-True (-not $Text.Contains('not offered (OK)') -and -not $Text.Contains('not vulnerable (OK)')) 'Unknown or unsupported probes do not produce false green verdicts'
Assert-True ($Text -match 'SSLv2\s+not tested: deadline reached') 'Skipped protocol preserves reason'
Assert-True ($Text -match 'SSLv3\s+not selected .*inconclusive') 'Alert remains inconclusive'
Assert-True ($Text -match 'TLS 1.3\s+offered \(HelloRetryRequest observed; selection only\)') 'TLS 1.3 selection does not imply completed handshake'
Assert-True ($Text -match 'BEAST / SSLv3 or TLS 1 CBC\s+catalog selection observed \(prerequisite only\)') 'Legacy CBC is presented only as an attack prerequisite'
Assert-True ($Text -match 'Heartbleed .*unsupported -- not tested') 'Unsupported vulnerabilities clearly disclosed'
Assert-True ($Text.Contains('Overall Grade') -and $Text.Contains('not assigned; severity counts are not an SSL Labs grade')) 'No fabricated rating or grade'
Assert-True ($Text.Contains('Header capture') -and $Text.Contains('INCOMPLETE -- missing-header verdicts not made')) 'Partial HTTP capture remains explicit'
Assert-True ($Text.IndexOf('[High] High finding') -lt $Text.IndexOf('[Low] Low finding')) 'Human findings sorted by severity'
Assert-True ($Text.Contains('Repeatable command') -and $Text.Contains($Long)) 'Commands and long evidence preserved'
Assert-True ($Text.Contains($Json)) 'Full canonical evidence JSON preserved verbatim in appendix'
$Report.Ciphers=@();$Report.Protocols=@();$Report.Extensions=@();$Report.Preference=@();$Report.Http=$null;$Report.Findings=@();$Report.Errors=@();$Report.Metadata.StartTls='smtp';$Report.Metadata.ChecksRequested=@('Certificate')
$Empty=New-TlsReportText $Report
Assert-True ($Empty.Contains('not applicable to selected STARTTLS service') -and $Empty.Contains('No findings recorded. This is not an all-clear')) 'Empty / STARTTLS reports do not imply HTTP testing or all-clear'
Assert-True ($Empty -match 'SSLv2\s+not tested \(check omitted or no result\)') 'Unrequested protocols are shown as not tested'
Assert-True ($Empty.Contains('not tested (no matching catalog probes)')) 'No cipher data does not become disabled-cipher verdict'
Assert-True ((ConvertTo-TlsTextTimestamp ([datetime]'2026-10-09T00:00:00Z')) -eq '2026-10-09 00:00:00 UTC') 'Imported date objects retain correct UTC rendering'
$Report.Metadata.StartedUtc=[datetime]'2026-10-09T00:00:00Z';$Report.Metadata.CompletedUtc=[datetime]'2026-10-09T00:00:02.345Z'
Assert-True ((New-TlsReportText $Report).Contains('[ 2.3s ]')) 'Fractional duration and imported date objects retain precision'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$Text | Set-Content -LiteralPath (Join-Path $OutputDirectory 'sample-tls-report.txt') -Encoding UTF8
$Empty | Set-Content -LiteralPath (Join-Path $OutputDirectory 'empty-tls-report.txt') -Encoding UTF8
Write-Host "PASS: $script:Assertions TXT report assertions on PowerShell $($PSVersionTable.PSVersion). Artifacts: $OutputDirectory"
