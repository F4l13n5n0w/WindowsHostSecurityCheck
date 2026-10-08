#Requires -Version 5.1
param([string]$OutputDirectory=(Join-Path $PSScriptRoot 'artifacts\tls'))
$ErrorActionPreference='Stop'
$Source=Join-Path (Split-Path $PSScriptRoot -Parent) 'testssl.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
foreach($definition in $ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($definition.Extent.Text))}
$script:Assertions=0
function Assert-True([bool]$Condition,[string]$Message){$script:Assertions++;if(-not $Condition){throw "FAILED: $Message"}}
function Assert-Throws([scriptblock]$Code,[string]$Message){$thrown=$false;try{& $Code | Out-Null}catch{$thrown=$true};Assert-True $thrown $Message}
Initialize-NativeTlsProbe
$endpoint=Resolve-TlsTarget 'https://localhost:8443/path?q=value' 0 '' '127.0.0.1'
Assert-True ($endpoint.Port -eq 8443 -and $endpoint.PathAndQuery -eq '/path?q=value') 'URL port and path preserved'
Assert-True ($endpoint.ConnectAddress -eq '127.0.0.1' -and $endpoint.ServerName -eq 'localhost') 'Connect override preserves SNI and validation name'
$ip6=Resolve-TlsTarget '[::1]:443' 0 '' '::1'
Assert-True ($ip6.ConnectAddress -eq '::1' -and $ip6.HostHeader -eq '[::1]') 'Bracketed IPv6 target'
Assert-Throws {Resolve-TlsTarget "localhost`r`nInjected: x" 0 '' ''} 'CRLF target rejected'
Assert-Throws {Resolve-TlsTarget 'https://user:secret@localhost' 0 '' ''} 'URL credentials rejected'
Assert-Throws {Resolve-TlsTarget 'http://localhost' 0 '' ''} 'Plain HTTP scheme rejected'
Assert-Throws {Resolve-TlsTarget 'localhost' 0 '' 'not-an-ip'} 'Connect address must be literal'
Assert-True ((ConvertTo-TlsLiteral "C:\app 'quoted'\testssl.ps1") -eq "'C:\app ''quoted''\testssl.ps1'") 'Command quoting doubles apostrophes'
$catalog=@(Get-TlsCipherCatalog)
Assert-True ($catalog.Count -eq 46 -and @($catalog | Group-Object Id | Where-Object Count -ne 1).Count -eq 0) 'Cipher catalog has 46 unique suites'
Assert-True (@($catalog | Where-Object {$_.Category -like 'TLS 1.3*'}).Count -eq 3) 'TLS 1.3 suites separate from legacy suites'
$hello=[WindowsTlsAudit.V1.Scanner]::BuildHello('localhost',771,[int[]]@(0xC02F),$false)
Assert-True ($hello[0] -eq 22 -and $hello[5] -eq 1 -and ($hello[3]*256+$hello[4]) -eq $hello.Length-5) 'ClientHello record framing'
Assert-True ([WindowsTlsAudit.V1.Scanner]::Hex($hello).Contains('6C6F63616C686F7374')) 'SNI DNS hostname encoded'
Assert-Throws {[WindowsTlsAudit.V1.Scanner]::BuildHello('localhost',771,[int[]]@(),$false)} 'Empty cipher offers rejected'
$body=[WindowsTlsAudit.V1.Scanner]::HexBytes('0303'+'00'*32+'00C02F00'+'0005FF01000100')
$parsed=[WindowsTlsAudit.V1.Scanner]::ParseServerHello($body)
Assert-True ($parsed.SelectedVersion -eq 771 -and $parsed.SelectedCipher -eq 0xC02F) 'ServerHello protocol and suite parsed'
Assert-True ($parsed.Extensions[0].Name -eq 'renegotiation_info') 'Secure renegotiation extension observed'
Assert-Throws {[WindowsTlsAudit.V1.Scanner]::ParseServerHello([byte[]]@(1,2))} 'Truncated ServerHello rejected'
Assert-Throws {[WindowsTlsAudit.V1.Scanner]::ParseServerHello([WindowsTlsAudit.V1.Scanner]::HexBytes('0303'+'00'*32+'21'))} 'Oversized session id rejected'
Assert-Throws {[WindowsTlsAudit.V1.Scanner]::ParseServerHello([WindowsTlsAudit.V1.Scanner]::HexBytes('0303'+'00'*32+'00C02F00'+'0004FF010010'))} 'Truncated extension rejected'
Assert-Throws {[WindowsTlsAudit.V1.Scanner]::ParseServerHello([WindowsTlsAudit.V1.Scanner]::HexBytes('0303'+'00'*32+'00C02F00'+'000AFF01000100FF01000100'))} 'Duplicate extension rejected'
$http=Get-TlsHttpAnalysis "HTTP/1.1 200 OK`r`nStrict-Transport-Security: max-age=31536000; includeSubDomains`r`nSet-Cookie: session=x; Secure; HttpOnly; SameSite=Lax`r`nSet-Cookie: theme=dark`r`n`r`n" $false
Assert-True ($http.HstsEnabled -and $http.HstsMaxAge -eq 31536000) 'HSTS positive max-age'
Assert-True ($http.Cookies.Count -eq 2 -and $http.Cookies[0].Secure -and $http.Cookies[0].HttpOnly -and -not $http.Cookies[1].Secure) 'Duplicate cookie headers retained and attributes interpreted'
Assert-True (-not (Get-TlsHttpAnalysis "HTTP/1.1 200 OK`r`nStrict-Transport-Security: max-age=0`r`n`r`n" $false).HstsEnabled) 'HSTS zero is disabled'
$huge=Get-TlsHttpAnalysis ("HTTP/1.1 200 OK`r`nStrict-Transport-Security: max-age="+('9'*100)+"`r`n`r`n") $false
Assert-True (-not $huge.HstsEnabled) 'Oversized attacker-controlled max-age does not crash parser'
Assert-True (@(Get-TlsCoverage | Where-Object Status -eq 'Unsupported').Count -ge 3) 'Unsupported probes explicitly disclosed'

# Local-only background C# fixtures. No external process or trust-store changes.
$Fixture=@'
using System;using System.IO;using System.Text;using System.Net;using System.Net.Sockets;using System.Net.Security;using System.Security.Authentication;using System.Security.Cryptography.X509Certificates;using System.Threading;using System.Collections.Generic;
namespace TlsAuditTests {
 public sealed class Server : IDisposable {
  TcpListener listener; Thread thread; volatile bool stopped; X509Certificate2 certificate; string mode; public int Port;
  public Server(string kind,X509Certificate2 cert){mode=kind;certificate=cert;listener=new TcpListener(IPAddress.Loopback,0);listener.Start();Port=((IPEndPoint)listener.LocalEndpoint).Port;thread=new Thread(Run);thread.IsBackground=true;thread.Start();}
  byte[] Read(Stream s,int size){byte[] b=new byte[size];int p=0;while(p<size){int n=s.Read(b,p,size-p);if(n==0)throw new EndOfStreamException();p+=n;}return b;}
  string Line(Stream s){List<byte>b=new List<byte>();for(int i=0;i<8192;i++){byte x=Read(s,1)[0];b.Add(x);if(x==10)return Encoding.ASCII.GetString(b.ToArray()).Trim();}throw new Exception("line limit");}
  void Send(Stream s,string line){byte[] b=Encoding.ASCII.GetBytes(line+"\r\n");s.Write(b,0,b.Length);}
  byte[] Bytes(string hex){byte[] b=new byte[hex.Length/2];for(int i=0;i<b.Length;i++)b[i]=Convert.ToByte(hex.Substring(i*2,2),16);return b;}
  void Frame(Stream s,byte[] body,bool split){List<byte> handshake=new List<byte>();handshake.Add(2);handshake.Add(0);handshake.Add((byte)(body.Length>>8));handshake.Add((byte)body.Length);handshake.AddRange(body);byte[] all=handshake.ToArray();int offset=0;while(offset<all.Length){int n=split?Math.Min(7,all.Length-offset):all.Length;byte[] header=new byte[]{22,3,3,(byte)(n>>8),(byte)n};s.Write(header,0,5);s.Write(all,offset,n);offset+=n;}}
  void Run(){while(!stopped){try{TcpClient c=listener.AcceptTcpClient();ThreadPool.QueueUserWorkItem(Handle,c);}catch{if(stopped)return;}}}
  void Handle(object state){using(TcpClient c=(TcpClient)state){try{Stream s=c.GetStream();s.ReadTimeout=2000;s.WriteTimeout=2000;
   if(mode=="smtp"||mode=="smtp-refused"){Send(s,"220 localhost fixture");if(!Line(s).StartsWith("EHLO"))return;Send(s,"250-localhost");Send(s,"250 STARTTLS");if(Line(s)!="STARTTLS")return;if(mode=="smtp-refused"){Send(s,"454 TLS temporarily unavailable");return;}Send(s,"220 Ready");}
   else if(mode=="ftp"){Send(s,"220 localhost fixture");if(Line(s)!="AUTH TLS")return;Send(s,"234 Ready");}
   else if(mode=="pop3"){Send(s,"+OK localhost fixture");if(Line(s)!="STLS")return;Send(s,"+OK Ready");}
   else if(mode=="imap"){Send(s,"* OK localhost fixture");if(Line(s)!="a001 STARTTLS")return;Send(s,"* CAPABILITY IMAP4rev1 STARTTLS");Send(s,"a001 OK Ready");}
   else if(mode=="postgres"){byte[] request=Read(s,8);if(BitConverter.ToString(request)!="00-00-00-08-04-D2-16-2F")return;s.WriteByte((byte)'S');}
   if(mode=="smtp"||mode=="ftp"||mode=="pop3"||mode=="imap"||mode=="postgres"||mode=="tls"||mode=="tls13"||mode=="partial-http") {using(SslStream ssl=new SslStream(s,false)){IAsyncResult a=ssl.BeginAuthenticateAsServer(certificate,false,mode=="tls13"?(SslProtocols)12288:SslProtocols.Tls12,false,null,null);using(WaitHandle h=a.AsyncWaitHandle){if(!h.WaitOne(2000))return;}ssl.EndAuthenticateAsServer(a);ssl.ReadTimeout=2000;ssl.WriteTimeout=2000;string first=Line(ssl);if(first.StartsWith("HEAD ")){while(Line(ssl)!=""){}if(mode=="partial-http"){byte[] part=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nX-Fixture: partial");ssl.Write(part,0,part.Length);return;}Send(ssl,"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\nSet-Cookie: session=fixture; Secure; HttpOnly; SameSite=Lax\r\nX-Fixture: <script>alert(1)</script>\r\nContent-Length: 0\r\nConnection: close\r\n");}}return;}
   if(mode=="stall"){Thread.Sleep(1500);return;}
   byte[] header=Read(s,5),payload=Read(s,header[3]*256+header[4]);
   if(mode=="alert"){byte[] b=Bytes("15030300020246");s.Write(b,0,b.Length);return;}
   if(mode=="oversize"){byte[] b=Bytes("160303FFFF");s.Write(b,0,b.Length);return;}
   if(mode=="partial-record"){byte[] b=Bytes("1603030010020000");s.Write(b,0,b.Length);return;}
   if(mode=="hrr"){byte[] sid=new byte[payload[38]];Array.Copy(payload,39,sid,0,sid.Length);List<byte>b=new List<byte>(Bytes("0303CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"));b.Add((byte)sid.Length);b.AddRange(sid);b.AddRange(Bytes("130100000C002B0002030400330002001D"));Frame(s,b.ToArray(),true);return;}
   byte[] body=Bytes("0303"+new string('0',64)+"00"+(mode=="unoffered"?"009C":"C02F")+"000005FF01000100");Frame(s,body,true);
  }catch{}}}
  public void Dispose(){stopped=true;listener.Stop();thread.Join(2000);}
 }
}
'@
Add-Type -TypeDefinition $Fixture -Language CSharp
foreach($mode in @('fragmented','alert','oversize','unoffered','hrr','stall','partial-record')) {
    $server=[TlsAuditTests.Server]::new($mode,$null)
    try {
        $version=if($mode -eq 'hrr'){772}else{771};$cipher=if($mode -eq 'hrr'){0x1301}else{0xC02F}
        $watch=[Diagnostics.Stopwatch]::StartNew()
        $probe=[WindowsTlsAudit.V1.Scanner]::Probe('127.0.0.1',$server.Port,'localhost','none',$version,[int[]]@($cipher),500,$false)
        switch($mode) {
            'fragmented' {Assert-True ($probe.Outcome -eq 'ServerHelloObserved' -and $probe.ResponseHex.Length -gt 0) ('Fragmented handshake reassembled and captured: '+$probe.Outcome+' / '+$probe.Error)}
            'alert' {Assert-True ($probe.Outcome -eq 'AlertReceived' -and $probe.Alerts[0] -match 'description=70') 'Protocol alert recorded without declaring pass'}
            'oversize' {Assert-True ($probe.Outcome -eq 'Inconclusive' -and $probe.CaptureLimitReached) 'Oversized record bounded'}
            'unoffered' {Assert-True ($probe.Outcome -eq 'Inconclusive' -and $probe.Error -match 'unoffered') 'Unoffered suite is not accepted'}
            'hrr' {Assert-True ($probe.Outcome -eq 'HelloRetryRequestObserved' -and $probe.SelectedVersion -eq 772) 'TLS 1.3 empty-share HRR validates echoed session and group'}
            'stall' {Assert-True ($probe.Outcome -eq 'Inconclusive' -and $watch.ElapsedMilliseconds -lt 1200) 'Per-probe timeout bounds stalled peer'}
            'partial-record' {Assert-True ($probe.Outcome -eq 'Inconclusive' -and $probe.ResponseHex -eq '1603030010020000') 'Partial record bytes retained when peer closes'}
        }
    } finally {$server.Dispose()}
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$OutputDirectory=(Resolve-Path -LiteralPath $OutputDirectory).Path
$rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048)
$rsa.PersistKeyInCsp=$false
$cert=$null;$server=$null
try {
    $request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=localhost',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $cert=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1),[DateTimeOffset]::UtcNow.AddDays(14))
    # A PFX round trip provides a Schannel-compatible private key on .NET Framework.
    $certBytes=$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx,'fixture-only')
    $cert.Dispose()
    $cert=[Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes,'fixture-only',[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    $server=[TlsAuditTests.Server]::new('tls',$cert)
    $session=[WindowsTlsAudit.V1.Scanner]::Session('127.0.0.1',$server.Port,'localhost','none',3072,5000,$false,"HEAD / HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n")
    Assert-True ($session.Success -and $session.Protocol -eq 'Tls12') ('Completed local TLS 1.2 handshake: '+$session.Error)
    Assert-True (-not $session.CertificateValid -and $session.PolicyErrors -match 'RemoteCertificateChainErrors') 'Untrusted fixture collected but never labeled trusted'
    Assert-True ($session.HttpResponse -match '^HTTP/1.1 200 OK' -and -not $session.HeaderLimitReached) 'HTTP headers captured over encrypted session'
    $details=Get-TlsCertificateDetails $session
    Assert-True ($details.KeyBits -eq 2048 -and $details.Sha256.Length -eq 64 -and $details.DaysRemaining -lt 30) 'Certificate key, fingerprint and lifetime extracted'
    $endpoint=Resolve-TlsTarget ('https://localhost:'+$server.Port+'/path?q=value') 0 '' '127.0.0.1'
    $saved=Invoke-NativeTlsAudit $endpoint 'none' @('Protocols','Ciphers','Certificate','Http','Extensions','Preference') 2 60 $false (Join-Path $OutputDirectory 'integration') $Source 6>$null
    Assert-True (@($saved.Report.Protocols | Where-Object {$_.Version -eq 771 -and $_.Selected}).Count -eq 1) 'Live TLS 1.2 selection observed independently of Schannel'
    Assert-True (@($saved.Report.Ciphers | Where-Object Selected).Count -gt 0) 'Individual cipher selection observed on local TLS server'
    Assert-True ($saved.Report.Certificate -and $saved.Report.Http.HstsEnabled) 'Full scan includes certificate and HTTP evidence'
    Assert-True (@($saved.Report.Findings | Where-Object Finding -like '*HSTS*').Count -eq 0) 'Valid HSTS response produces no missing-header finding'
    Assert-True (@($saved.Report.Findings | Where-Object Finding -eq 'Certificate validation failed').Count -eq 1) 'Untrusted certificate reported'
    $html=Get-Content -LiteralPath $saved.HtmlPath -Raw
    Assert-True ($html.Contains('alert(1)') -and -not $html.Contains('X-Fixture: <script>')) 'Server-controlled strings safely encoded on both JSON serializers'
    Assert-True ($html.Contains('Heartbleed') -and $html.Contains('Unsupported') -and $html.Contains('data-rank="1"')) 'HTML includes unsupported coverage and sortable severity'
    $txt=Get-Content -LiteralPath ([IO.Path]::ChangeExtension($saved.JsonPath,'txt')) -Raw
    Assert-True ($txt.StartsWith('#'*69) -and $txt.Contains("Testing server's cipher preferences")) 'Scan TXT uses the template-style banner and section layout'
    Assert-True ($txt.Contains((Get-Content -LiteralPath $saved.JsonPath -Raw).TrimEnd())) 'Scan TXT retains the full JSON evidence appendix'
    Assert-True ($txt.Contains('localhost') -and -not $txt.Contains('www.levelblue.com')) 'Scan TXT renders actual target rather than template values'
    foreach($finding in $saved.Report.Findings){$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseInput($finding.Command,[ref]$t,[ref]$e);Assert-True ($e.Count -eq 0) 'Repeatable command syntax parses';Assert-True (([regex]::Matches($finding.Command,' -Target ')).Count -eq 1) 'Repeatable command has one target argument'}
    $manifest=Get-ChildItem -LiteralPath (Split-Path $saved.JsonPath -Parent) -Filter '*_SHA256.txt' | Select-Object -First 1
    foreach($line in Get-Content -LiteralPath $manifest.FullName){$parts=$line -split '  ',2;Assert-True ((Get-FileHash -LiteralPath (Join-Path $manifest.DirectoryName $parts[1])).Hash -eq $parts[0]) 'Artifact SHA256 matches'}
    $cli=@(& $Source -Target ('https://localhost:'+$server.Port+'/path') -ConnectAddress '127.0.0.1' -Checks Certificate,Http -OutputDirectory (Join-Path $OutputDirectory 'cli') 6>$null)
    Assert-True ($cli.Count -eq 1 -and (Test-Path -LiteralPath $cli[0].HtmlPath)) 'Standalone CLI runs without helper files'
    foreach($mode in @('smtp','imap','pop3','ftp','postgres')) {
        $upgrade=[TlsAuditTests.Server]::new($mode,$cert)
        try {$mail=[WindowsTlsAudit.V1.Scanner]::Session('127.0.0.1',$upgrade.Port,'localhost',$mode,3072,5000,$false,'');Assert-True ($mail.Success -and $mail.StartTlsTranscript.Length -gt 0) ($mode+' upgrade and completed TLS handshake: '+$mail.Error)} finally {$upgrade.Dispose()}
    }
    $refused=[TlsAuditTests.Server]::new('smtp-refused',$cert)
    try {$mail=[WindowsTlsAudit.V1.Scanner]::Session('127.0.0.1',$refused.Port,'localhost','smtp',3072,5000,$false,'');Assert-True (-not $mail.Success -and $mail.StartTlsTranscript.Contains('454')) 'STARTTLS refusal preserved, not treated as successful upgrade'} finally {$refused.Dispose()}
    $partial=[TlsAuditTests.Server]::new('partial-http',$cert)
    try {$partialResponse=[WindowsTlsAudit.V1.Scanner]::Session('127.0.0.1',$partial.Port,'localhost','none',3072,5000,$false,"HEAD / HTTP/1.1`r`nHost: localhost`r`n`r`n");Assert-True ($partialResponse.HeaderLimitReached -and $partialResponse.HttpResponse.Contains('X-Fixture: partial')) 'Partial HTTP headers preserved and marked incomplete'} finally {$partial.Dispose()}
    $tls13=[TlsAuditTests.Server]::new('tls13',$cert)
    try {$selection=[WindowsTlsAudit.V1.Scanner]::Probe('127.0.0.1',$tls13.Port,'localhost','none',772,[int[]]@(0x1301,0x1302,0x1303),3000,$false);if($selection.Outcome -eq 'HelloRetryRequestObserved'){Assert-True ($selection.SelectedVersion -eq 772) 'Real Windows TLS 1.3 server returns validated HRR'}else{Write-Host ('Local TLS 1.3 fixture unavailable on this OS/runtime: '+$selection.Error+' '+$selection.Outcome)}} finally {$tls13.Dispose()}
} finally {if($server){$server.Dispose()};if($cert){$cert.Dispose()};$rsa.Dispose()}
Write-Host "PASS: $script:Assertions TLS assertions on PowerShell $($PSVersionTable.PSVersion). Artifacts: $OutputDirectory"
