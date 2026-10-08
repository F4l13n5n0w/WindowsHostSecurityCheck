#Requires -Version 5.1
<#
.SYNOPSIS
Native Windows TLS/SSL configuration scanner, inspired by testssl.sh.
.DESCRIPTION
Uses .NET sockets, bounded TLS ClientHello probes and SslStream. No external
executables, containers, modules or Linux runtime are required. A ServerHello
is evidence of selection, not a completed/authenticated TLS session. Unsupported
testssl.sh checks are explicitly listed in every report. No upstream code is copied.
.EXAMPLE
.\testssl.ps1 -Target https://server.example:443 -OutputDirectory C:\Temp\TLSReport
.EXAMPLE
.\testssl.ps1 -Target mail.example:25 -StartTls smtp -Checks Protocols,Certificate
.EXAMPLE
.\testssl.ps1 -Target server.example:8443 -ConnectAddress 10.0.0.20 -ServerName server.example
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true,Position=0)][ValidateNotNullOrEmpty()][string]$Target,
    [ValidateRange(1,65535)][int]$Port,
    [string]$ServerName='',
    [string]$ConnectAddress='',
    [ValidateSet('none','smtp','imap','pop3','ftp','postgres')][string]$StartTls='none',
    [ValidateSet('Protocols','Ciphers','Certificate','Http','Extensions','Preference')][string[]]$Checks=@('Protocols','Ciphers','Certificate','Http','Extensions','Preference'),
    [ValidateRange(1,120)][int]$TimeoutSeconds=5,
    [ValidateRange(1,7200)][int]$ScanTimeoutSeconds=600,
    [switch]$CheckRevocation,
    [string]$OutputDirectory='.\TLSReport'
)
$ErrorActionPreference='Stop'

function Initialize-NativeTlsProbe {
    if ('WindowsTlsAudit.V1.Scanner' -as [type]) {return}
    $Code=@'
using System;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Diagnostics;
namespace WindowsTlsAudit.V1 {
 public sealed class Extension { public int Id; public string Name, Hex; }
 public sealed class HelloResult {
  public string Outcome="NotNegotiated", Error="", RequestHex="", ResponseHex="", StartTlsTranscript="";
  public int RequestedVersion, SelectedVersion=-1, SelectedCipher=-1, Compression=-1, SessionIdLength;
  public bool HelloRetryRequest, CaptureLimitReached;
  public List<Extension> Extensions=new List<Extension>();
  public List<string> Alerts=new List<string>();
 }
 public sealed class SessionResult {
  public bool Success, CertificateValid, HeaderLimitReached;
  public string Error="", Protocol="", CipherSuite="", CipherAlgorithm="", KeyExchangeAlgorithm="", HashAlgorithm="", PolicyErrors="", CertificateBase64="", HttpResponse="", StartTlsTranscript="";
  public int CipherStrength, KeyExchangeStrength, HashStrength;
  public List<string> ChainCertificates=new List<string>(), ChainStatus=new List<string>();
 }
 public static class Scanner {
  const int CaptureLimit=131072;
  static readonly byte[] RetryRandom=HexBytes("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");
  public static byte[] HexBytes(string s) {if(s.Length%2!=0)throw new FormatException("Odd hex length");byte[] b=new byte[s.Length/2];for(int i=0;i<b.Length;i++)b[i]=Convert.ToByte(s.Substring(i*2,2),16);return b;}
  public static string Hex(byte[] b){return BitConverter.ToString(b).Replace("-","");}
  static int U16(byte[] b,int p){if(p<0||p+2>b.Length)throw new InvalidDataException("Truncated uint16");return b[p]*256+b[p+1];}
  static void Word(List<byte> b,int n){b.Add((byte)(n>>8));b.Add((byte)n);}
  static byte[] RandomBytes(int n){byte[] b=new byte[n];using(RandomNumberGenerator r=RandomNumberGenerator.Create())r.GetBytes(b);return b;}
  static void Ext(List<byte> b,int type,byte[] data){Word(b,type);Word(b,data.Length);b.AddRange(data);}
  public static byte[] BuildHello(string name,int version,int[] suites,bool fallback) {
   if(suites==null||suites.Length==0||suites.Length>1024)throw new ArgumentException("Invalid suite count");
   List<byte> hello=new List<byte>();int legacy=version==0x0304?0x0303:version;
   Word(hello,legacy);hello.AddRange(RandomBytes(32));byte[] session=version==0x0304?RandomBytes(32):new byte[0];hello.Add((byte)session.Length);hello.AddRange(session);
   List<byte> cipher=new List<byte>();foreach(int suite in suites){if(suite<0||suite>65535)throw new ArgumentException("Invalid suite");Word(cipher,suite);}
   if(version<0x0304)Word(cipher,0x00ff);if(fallback)Word(cipher,0x5600);Word(hello,cipher.Count);hello.AddRange(cipher);hello.Add((byte)(version==0x0304?1:2));hello.Add(0);if(version!=0x0304)hello.Add(1);
   if(version>=0x0301) {
    List<byte> extensions=new List<byte>();IPAddress ip;
    if(!String.IsNullOrEmpty(name)&&!IPAddress.TryParse(name,out ip)){
     byte[] host=Encoding.ASCII.GetBytes(name);List<byte> sni=new List<byte>();Word(sni,host.Length+3);sni.Add(0);Word(sni,host.Length);sni.AddRange(host);Ext(extensions,0,sni.ToArray());
    }
    Ext(extensions,10,HexBytes("0008001D001700180100")); // x25519, P-256, P-384, ffdhe2048
    Ext(extensions,11,HexBytes("0100"));
    Ext(extensions,13,HexBytes("00140403050306030804080508060809040105010201"));
    Ext(extensions,35,new byte[0]);
    // HTTP ALPN is omitted: raw probes are service-neutral. HTTP uses HTTP/1.1.
    if(version==0x0304){Ext(extensions,43,HexBytes("020304"));Ext(extensions,51,HexBytes("0000"));} // valid empty key share requests HRR
    Word(hello,extensions.Count);hello.AddRange(extensions);
   }
   List<byte> handshake=new List<byte>();handshake.Add(1);handshake.Add((byte)(hello.Count>>16));Word(handshake,hello.Count);handshake.AddRange(hello);
   List<byte> record=new List<byte>();record.Add(22);Word(record,version>=0x0303?0x0301:version);Word(record,handshake.Count);record.AddRange(handshake);return record.ToArray();
  }
  public static HelloResult ParseServerHello(byte[] body) {
   HelloResult r=new HelloResult();if(body==null||body.Length<38)throw new InvalidDataException("Truncated ServerHello");
   r.SelectedVersion=U16(body,0);byte[] random=new byte[32];Array.Copy(body,2,random,0,32);r.HelloRetryRequest=Hex(random)==Hex(RetryRandom);
   int p=34,n=body[p++];if(n>32||p+n+3>body.Length)throw new InvalidDataException("Invalid session id length");r.SessionIdLength=n;p+=n;
   r.SelectedCipher=U16(body,p);p+=2;r.Compression=body[p++];
   if(p<body.Length){int count=U16(body,p);p+=2;if(p+count!=body.Length)throw new InvalidDataException("Extension length mismatch");int end=p+count;
    HashSet<int> ids=new HashSet<int>();while(p<end){if(p+4>end)throw new InvalidDataException("Truncated extension header");int id=U16(body,p),len=U16(body,p+2);p+=4;if(p+len>end||!ids.Add(id))throw new InvalidDataException("Malformed/duplicate extension");byte[] value=new byte[len];Array.Copy(body,p,value,0,len);p+=len;
     string label=id==0?"server_name":id==5?"status_request":id==10?"supported_groups":id==11?"ec_point_formats":id==16?"ALPN":id==35?"session_ticket":id==43?"supported_versions":id==51?"key_share":id==65281?"renegotiation_info":"extension_"+id;
     r.Extensions.Add(new Extension{Id=id,Name=label,Hex=Hex(value)});
     if(id==43){if(len!=2)throw new InvalidDataException("Invalid selected version");r.SelectedVersion=U16(value,0);}
    }
   }
   if(r.SelectedVersion==0x0304&&(r.Compression!=0||!r.Extensions.Exists(e=>e.Id==43)))throw new InvalidDataException("Invalid TLS 1.3 ServerHello");
   r.Outcome=r.HelloRetryRequest?"HelloRetryRequestObserved":"ServerHelloObserved";return r;
  }
  static int Remaining(Stopwatch watch,int timeout){int ms=timeout-(int)watch.ElapsedMilliseconds;if(ms<=0)throw new TimeoutException("Probe deadline reached");return ms;}
  static string Property(SslStream ssl,string name){try{System.Reflection.PropertyInfo p=ssl.GetType().GetProperty(name);return p==null?"":Convert.ToString(p.GetValue(ssl,null));}catch{return "";}}
  static int NumberProperty(SslStream ssl,string name){int value;return Int32.TryParse(Property(ssl,name),out value)?value:0;}
  static TcpClient Connect(string ip,int port,Stopwatch watch,int timeout){TcpClient c=new TcpClient(IPAddress.Parse(ip).AddressFamily);try{IAsyncResult a=c.BeginConnect(IPAddress.Parse(ip),port,null,null);using(System.Threading.WaitHandle h=a.AsyncWaitHandle){if(!h.WaitOne(Remaining(watch,timeout)))throw new TimeoutException("TCP connect timed out");}c.EndConnect(a);return c;}catch{c.Close();throw;}}
  static byte[] ReadExact(Stream s,int n,Stopwatch watch,int timeout,List<byte> capture=null){byte[] b=new byte[n];int p=0;while(p<n){s.ReadTimeout=Remaining(watch,timeout);int read=s.Read(b,p,n-p);if(read==0)throw new EndOfStreamException("Peer closed connection");if(capture!=null)for(int i=p;i<p+read;i++)capture.Add(b[i]);p+=read;}return b;}
  static string ReadLine(Stream s,Stopwatch watch,int timeout,StringBuilder log){List<byte> b=new List<byte>();while(b.Count<8192){byte x=ReadExact(s,1,watch,timeout)[0];b.Add(x);if(x==10){string line=Encoding.ASCII.GetString(b.ToArray()).TrimEnd('\r','\n');if(log.Length+line.Length>32768)throw new InvalidDataException("STARTTLS transcript limit");log.AppendLine("S: "+line);return line;}}throw new InvalidDataException("STARTTLS line limit");}
  static void Send(Stream s,string line,StringBuilder log,Stopwatch watch,int timeout){byte[] b=Encoding.ASCII.GetBytes(line+"\r\n");s.WriteTimeout=Remaining(watch,timeout);s.Write(b,0,b.Length);log.AppendLine("C: "+line);}
  static void Reply(Stream s,string code,Stopwatch watch,int timeout,StringBuilder log){for(int i=0;i<100;i++){string line=ReadLine(s,watch,timeout,log);if(line.Length<3||!line.StartsWith(code,StringComparison.Ordinal))throw new InvalidDataException("Unexpected STARTTLS reply: "+line);if(line.Length==3||line[3]==' ')return;if(line[3]!='-')throw new InvalidDataException("Malformed multiline reply");}throw new InvalidDataException("STARTTLS reply line limit");}
  static void Upgrade(Stream s,string mode,Stopwatch watch,int timeout,StringBuilder log){
   if(mode=="none")return;
   if(mode=="smtp"){Reply(s,"220",watch,timeout,log);Send(s,"EHLO tls-audit.invalid",log,watch,timeout);Reply(s,"250",watch,timeout,log);Send(s,"STARTTLS",log,watch,timeout);Reply(s,"220",watch,timeout,log);}
   else if(mode=="ftp"){Reply(s,"220",watch,timeout,log);Send(s,"AUTH TLS",log,watch,timeout);Reply(s,"234",watch,timeout,log);}
   else if(mode=="pop3"){if(!ReadLine(s,watch,timeout,log).StartsWith("+OK",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("POP3 greeting rejected");Send(s,"STLS",log,watch,timeout);if(!ReadLine(s,watch,timeout,log).StartsWith("+OK",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("POP3 STLS rejected");}
   else if(mode=="imap"){if(!ReadLine(s,watch,timeout,log).StartsWith("* OK",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("IMAP greeting rejected");Send(s,"a001 STARTTLS",log,watch,timeout);for(int i=0;i<100;i++){string line=ReadLine(s,watch,timeout,log);if(line.StartsWith("a001 ",StringComparison.OrdinalIgnoreCase)){if(!line.StartsWith("a001 OK",StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("IMAP STARTTLS rejected");return;}}throw new InvalidDataException("IMAP reply line limit");}
   else if(mode=="postgres"){byte[] b=HexBytes("0000000804D2162F");s.WriteTimeout=Remaining(watch,timeout);s.Write(b,0,b.Length);log.AppendLine("C: PostgreSQL SSLRequest 0000000804D2162F");byte response=ReadExact(s,1,watch,timeout)[0];log.AppendLine("S: "+(char)response);if(response!=(byte)'S')throw new InvalidDataException("PostgreSQL TLS upgrade rejected");}
   else throw new ArgumentException("Unsupported STARTTLS protocol");
  }
  public static HelloResult Probe(string ip,int port,string name,string startTls,int version,int[] suites,int timeout,bool fallback){
   HelloResult r=new HelloResult{RequestedVersion=version};Stopwatch watch=Stopwatch.StartNew();StringBuilder log=new StringBuilder();List<byte> captured=new List<byte>();TcpClient c=null;
   try{c=Connect(ip,port,watch,timeout);NetworkStream s=c.GetStream();Upgrade(s,startTls,watch,timeout,log);byte[] request=BuildHello(name,version,suites,fallback);r.RequestHex=Hex(request);s.WriteTimeout=Remaining(watch,timeout);s.Write(request,0,request.Length);
    List<byte> messages=new List<byte>();for(int i=0;i<32;i++){byte[] header=ReadExact(s,5,watch,timeout,captured);int len=U16(header,3);if(len>18432||captured.Count+len>CaptureLimit){r.CaptureLimitReached=true;throw new InvalidDataException("TLS record/capture limit exceeded");}byte[] payload=ReadExact(s,len,watch,timeout,captured);
     if(header[0]==21){if(payload.Length>=2){r.Alerts.Add("level="+payload[0]+", description="+payload[1]);r.Outcome="AlertReceived";break;}throw new InvalidDataException("Truncated TLS alert");}
     if(header[0]!=22)throw new InvalidDataException("Unexpected TLS record type "+header[0]);messages.AddRange(payload);
     while(messages.Count>=4){int size=messages[1]*65536+messages[2]*256+messages[3];if(size>CaptureLimit)throw new InvalidDataException("Handshake length limit");if(messages.Count<4+size)break;byte type=messages[0];byte[] body=messages.GetRange(4,size).ToArray();messages.RemoveRange(0,4+size);if(type==2){HelloResult parsed=ParseServerHello(body);if(Array.IndexOf(suites,parsed.SelectedCipher)<0)throw new InvalidDataException("Server selected an unoffered cipher");if(parsed.SelectedVersion!=version)throw new InvalidDataException("Server selected a different protocol");if(parsed.Compression>1)throw new InvalidDataException("Server selected unoffered compression");
      if(version==0x0304){if(!parsed.HelloRetryRequest||parsed.SessionIdLength!=32||U16(body,0)!=0x0303)throw new InvalidDataException("Expected TLS 1.3 HelloRetryRequest");byte[] sentId=new byte[32],echoId=new byte[32];Array.Copy(request,44,sentId,0,32);Array.Copy(body,35,echoId,0,32);if(Hex(sentId)!=Hex(echoId))throw new InvalidDataException("TLS 1.3 session id echo mismatch");Extension share=parsed.Extensions.Find(e=>e.Id==51);if(share==null||!(share.Hex=="001D"||share.Hex=="0017"||share.Hex=="0018"||share.Hex=="0100"))throw new InvalidDataException("HRR selected an unoffered group");}
      else if(parsed.HelloRetryRequest)throw new InvalidDataException("Unexpected HelloRetryRequest for legacy protocol");
      parsed.RequestedVersion=version;parsed.RequestHex=r.RequestHex;r=parsed;return r;}throw new InvalidDataException("Unexpected first handshake type "+type);}
    }
    if(r.Outcome!="AlertReceived"){r.CaptureLimitReached=true;throw new InvalidDataException("No ServerHello within record count limit");}
   }catch(Exception e){r.Error=e.GetBaseException().Message;if(r.Outcome!="AlertReceived")r.Outcome="Inconclusive";}
   finally{r.ResponseHex=Hex(captured.ToArray());r.StartTlsTranscript=log.ToString();if(c!=null)c.Close();}
   return r;
  }
  public static HelloResult ProbeSsl2(string ip,int port,string startTls,int timeout){
   HelloResult r=new HelloResult{RequestedVersion=2};TcpClient c=null;Stopwatch watch=Stopwatch.StartNew();StringBuilder log=new StringBuilder();List<byte> captured=new List<byte>();
   try{c=Connect(ip,port,watch,timeout);Stream s=c.GetStream();Upgrade(s,startTls,watch,timeout,log);byte[] specs=HexBytes("0100800200800300800400800500800600400700C0");List<byte> b=new List<byte>();b.Add(1);Word(b,2);Word(b,specs.Length);Word(b,0);Word(b,16);b.AddRange(specs);b.AddRange(RandomBytes(16));List<byte> record=new List<byte>();record.Add((byte)(0x80|(b.Count>>8)));record.Add((byte)b.Count);record.AddRange(b);byte[] request=record.ToArray();r.RequestHex=Hex(request);s.WriteTimeout=Remaining(watch,timeout);s.Write(request,0,request.Length);
    byte[] header=ReadExact(s,2,watch,timeout,captured);if((header[0]&0x80)==0)throw new InvalidDataException("No SSLv2 short-header response");int len=(header[0]&0x7f)*256+header[1];byte[] response=ReadExact(s,len,watch,timeout,captured);if(len<11||response[0]!=4||U16(response,3)!=2)throw new InvalidDataException("No valid SSLv2 ServerHello");int cert=U16(response,5),cipher=U16(response,7),conn=U16(response,9);if(cipher%3!=0||11+cert+cipher+conn!=len)throw new InvalidDataException("Invalid SSLv2 ServerHello lengths");r.SelectedVersion=2;r.Outcome="ServerHelloObserved";
   }catch(Exception e){r.Error=e.GetBaseException().Message;r.Outcome="Inconclusive";}finally{r.ResponseHex=Hex(captured.ToArray());r.StartTlsTranscript=log.ToString();if(c!=null)c.Close();}return r;
  }
  public static SessionResult Session(string ip,int port,string name,string startTls,int protocol,int timeout,bool revocation,string request){
   SessionResult r=new SessionResult();Stopwatch watch=Stopwatch.StartNew();TcpClient c=null;SslStream ssl=null;StringBuilder log=new StringBuilder();List<byte> response=new List<byte>();
   if(!String.IsNullOrEmpty(request))r.HeaderLimitReached=true;
   try{c=Connect(ip,port,watch,timeout);NetworkStream net=c.GetStream();Upgrade(net,startTls,watch,timeout,log);
    ssl=new SslStream(net,false,delegate(object sender,X509Certificate cert,X509Chain chain,SslPolicyErrors errors){
     r.PolicyErrors=errors.ToString();r.CertificateValid=errors==SslPolicyErrors.None;
     if(cert!=null)r.CertificateBase64=Convert.ToBase64String(cert.Export(X509ContentType.Cert));
     if(chain!=null){foreach(X509ChainElement element in chain.ChainElements)r.ChainCertificates.Add(Convert.ToBase64String(element.Certificate.RawData));foreach(X509ChainStatus status in chain.ChainStatus)r.ChainStatus.Add(status.Status+": "+status.StatusInformation.Trim());}
     return true; // Per-connection audit only. Validation failures are recorded, never called trusted.
    });
    IAsyncResult auth=ssl.BeginAuthenticateAsClient(name,new X509CertificateCollection(),(SslProtocols)protocol,revocation,null,null);
    using(System.Threading.WaitHandle h=auth.AsyncWaitHandle){if(!h.WaitOne(Remaining(watch,timeout)))throw new TimeoutException("TLS authentication timed out");}ssl.EndAuthenticateAsClient(auth);
    r.Success=true;r.Protocol=ssl.SslProtocol.ToString();r.CipherAlgorithm=Property(ssl,"CipherAlgorithm");r.CipherStrength=NumberProperty(ssl,"CipherStrength");r.KeyExchangeAlgorithm=Property(ssl,"KeyExchangeAlgorithm");r.KeyExchangeStrength=NumberProperty(ssl,"KeyExchangeStrength");r.HashAlgorithm=Property(ssl,"HashAlgorithm");r.HashStrength=NumberProperty(ssl,"HashStrength");
    System.Reflection.PropertyInfo property=ssl.GetType().GetProperty("NegotiatedCipherSuite");if(property!=null){try{r.CipherSuite=Convert.ToString(property.GetValue(ssl,null));}catch{}}
    if(!String.IsNullOrEmpty(request)){byte[] bytes=Encoding.ASCII.GetBytes(request);ssl.WriteTimeout=Remaining(watch,timeout);ssl.Write(bytes,0,bytes.Length);int state=0;
     while(response.Count<65536){byte x=ReadExact(ssl,1,watch,timeout)[0];response.Add(x);state=(state==0&&x==13)?1:(state==1&&x==10)?2:(state==2&&x==13)?3:(state==3&&x==10)?4:0;if(state==4)break;}
     r.HeaderLimitReached=state!=4;r.HttpResponse=Encoding.GetEncoding(28591).GetString(response.ToArray());
    }
   }catch(Exception e){r.Error=e.GetBaseException().Message;}finally{if(response.Count>0)r.HttpResponse=Encoding.GetEncoding(28591).GetString(response.ToArray());r.StartTlsTranscript=log.ToString();if(ssl!=null)ssl.Dispose();if(c!=null)c.Close();}return r;
  }
 }
}
'@
    Add-Type -TypeDefinition $Code -Language CSharp
}

function ConvertTo-TlsLiteral {param([string]$Value) return "'"+$Value.Replace("'","''")+"'"}
function ConvertTo-TlsHtml {param($Value) return [Net.WebUtility]::HtmlEncode([string]$Value)}

function Resolve-TlsTarget {
    param([string]$Value,[int]$PortOverride,[string]$Sni,[string]$Address,[int]$DnsTimeoutSeconds=5)
    if ($Value -match '[\x00-\x20\x7F]' -or $Value.StartsWith('-')) {throw 'Target contains invalid characters.'}
    $Uri=$null
    $InputUri=if ($Value -match '^https://') {$Value} elseif ($Value -match '^[a-z]+://') {throw 'Only https:// URLs or host[:port] targets are accepted.'} else {'https://'+$Value}
    if (-not [uri]::TryCreate($InputUri,[UriKind]::Absolute,[ref]$Uri) -or $Uri.Scheme -ne 'https' -or $Uri.UserInfo -or $Uri.Fragment) {throw 'Invalid TLS target; credentials and URL fragments are not accepted.'}
    $Name=$Uri.DnsSafeHost.Trim('[',']')
    if (-not $Name) {throw 'Target hostname is empty.'}
    $HostIp=$null
    if ([Net.IPAddress]::TryParse($Name,[ref]$HostIp)) {$Name=$HostIp.ToString()}
    $SelectedPort=if ($PortOverride) {$PortOverride} else {$Uri.Port}
    $Server=if ($Sni) {$Sni} else {$Name}
    if ($Server -match '[\x00-\x20\x7F/:\\]' -and -not ($Server -match '^[0-9A-Fa-f:]+$')) {throw 'Invalid ServerName.'}
    $Server=(New-Object Globalization.IdnMapping).GetAscii($Server)
    $ParsedIp=$null
    $Addresses=if ($Address) {
        if (-not [Net.IPAddress]::TryParse($Address.Trim('[',']'),[ref]$ParsedIp)) {throw 'ConnectAddress must be a literal IP address.'}
        @($ParsedIp)
    } else {
        $Lookup=[Net.Dns]::GetHostAddressesAsync($Name)
        if (-not $Lookup.Wait($DnsTimeoutSeconds*1000)) {throw 'DNS lookup timed out.'}
        @($Lookup.GetAwaiter().GetResult())
    }
    if (-not $Addresses.Count) {throw 'No addresses were resolved.'}
    $Selected=@($Addresses | Sort-Object @{Expression={if($_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork){0}else{1}}})[0]
    $HostHeader=if ($Server.Contains(':')) {'['+$Server+']'} else {$Server}
    if ($SelectedPort -ne 443) {$HostHeader+=':'+$SelectedPort}
    [pscustomobject]@{Host=$Name;Port=$SelectedPort;ServerName=$Server;ConnectAddress=$Selected.ToString();ResolvedAddresses=@($Addresses | ForEach-Object {$_.ToString()});PathAndQuery=$Uri.PathAndQuery;HostHeader=$HostHeader}
}

function Get-TlsCipherCatalog {
    # Deliberately explicit catalog, not a claim to cover every IANA suite.
    $Rows=@'
0001|TLS_RSA_WITH_NULL_MD5|Critical|NULL encryption|No
0002|TLS_RSA_WITH_NULL_SHA|Critical|NULL encryption|No
0003|TLS_RSA_EXPORT_WITH_RC4_40_MD5|Critical|EXPORT RC4|No
0004|TLS_RSA_WITH_RC4_128_MD5|High|RC4|No
0005|TLS_RSA_WITH_RC4_128_SHA|High|RC4|No
0008|TLS_RSA_EXPORT_WITH_DES40_CBC_SHA|Critical|EXPORT DES|No
0009|TLS_RSA_WITH_DES_CBC_SHA|High|DES|No
000A|TLS_RSA_WITH_3DES_EDE_CBC_SHA|High|64-bit block / 3DES|No
0014|TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA|Critical|EXPORT DH|Yes
0016|TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA|High|64-bit block / 3DES|Yes
0018|TLS_DH_anon_WITH_RC4_128_MD5|Critical|Anonymous authentication|Yes
001B|TLS_DH_anon_WITH_3DES_EDE_CBC_SHA|Critical|Anonymous authentication|Yes
002F|TLS_RSA_WITH_AES_128_CBC_SHA|Medium|CBC / static RSA|No
0033|TLS_DHE_RSA_WITH_AES_128_CBC_SHA|Low|CBC|Yes
0034|TLS_DH_anon_WITH_AES_128_CBC_SHA|Critical|Anonymous authentication|Yes
0035|TLS_RSA_WITH_AES_256_CBC_SHA|Medium|CBC / static RSA|No
0039|TLS_DHE_RSA_WITH_AES_256_CBC_SHA|Low|CBC|Yes
003C|TLS_RSA_WITH_AES_128_CBC_SHA256|Medium|CBC / static RSA|No
003D|TLS_RSA_WITH_AES_256_CBC_SHA256|Medium|CBC / static RSA|No
0067|TLS_DHE_RSA_WITH_AES_128_CBC_SHA256|Low|CBC|Yes
006B|TLS_DHE_RSA_WITH_AES_256_CBC_SHA256|Low|CBC|Yes
009C|TLS_RSA_WITH_AES_128_GCM_SHA256|Medium|AEAD / static RSA|No
009D|TLS_RSA_WITH_AES_256_GCM_SHA384|Medium|AEAD / static RSA|No
009E|TLS_DHE_RSA_WITH_AES_128_GCM_SHA256|Informational|AEAD|Yes
009F|TLS_DHE_RSA_WITH_AES_256_GCM_SHA384|Informational|AEAD|Yes
C007|TLS_ECDHE_ECDSA_WITH_RC4_128_SHA|High|RC4|Yes
C009|TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA|Low|CBC|Yes
C00A|TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA|Low|CBC|Yes
C011|TLS_ECDHE_RSA_WITH_RC4_128_SHA|High|RC4|Yes
C012|TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA|High|64-bit block / 3DES|Yes
C013|TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA|Low|CBC|Yes
C014|TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA|Low|CBC|Yes
C023|TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256|Low|CBC|Yes
C024|TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384|Low|CBC|Yes
C027|TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256|Low|CBC|Yes
C028|TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384|Low|CBC|Yes
C02B|TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256|Informational|AEAD|Yes
C02C|TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384|Informational|AEAD|Yes
C02F|TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256|Informational|AEAD|Yes
C030|TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384|Informational|AEAD|Yes
CCA8|TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256|Informational|AEAD|Yes
CCA9|TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256|Informational|AEAD|Yes
CCAA|TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256|Informational|AEAD|Yes
1301|TLS_AES_128_GCM_SHA256|Informational|TLS 1.3 AEAD|Not established by HRR
1302|TLS_AES_256_GCM_SHA384|Informational|TLS 1.3 AEAD|Not established by HRR
1303|TLS_CHACHA20_POLY1305_SHA256|Informational|TLS 1.3 AEAD|Not established by HRR
'@
    foreach ($Line in ($Rows -split '\r?\n')) {$Fields=$Line.Split('|');[pscustomobject]@{Id=[Convert]::ToInt32($Fields[0],16);Hex=$Fields[0];Name=$Fields[1];Severity=$Fields[2];Category=$Fields[3];ForwardSecrecy=$Fields[4]}}
}

function Get-TlsCoverage {
    @(
        [pscustomobject]@{Check='SSLv2 / SSLv3 / TLS 1.0-1.3';Status='Implemented';Explanation='Raw ClientHello / ServerHello selection probes; TLS 1.3 uses an empty key share and expects HelloRetryRequest. Native completed handshake is recorded separately.'}
        [pscustomobject]@{Check='Cipher categories / individual ciphers';Status='Partial';Explanation='46 explicitly listed suites, one suite per probe, on every observed TLS protocol. Selection does not complete authentication. Catalog excludes many PSK, CCM, GOST, Camellia and other suites.'}
        [pscustomobject]@{Check='Cipher preference / forward secrecy';Status='Partial';Explanation='Two order-reversed offers for observed TLS 1.2/1.3 suites. FS is inferred from selected pre-TLS-1.3 suite type; DH parameter strength and full group enumeration are not tested.'}
        [pscustomobject]@{Check='Certificate / trust / hostname / validity / key / signature';Status='Implemented';Explanation='Completed SslStream handshake; Windows trust store and name validation. Optional revocation follows Windows chain policy and may contact certificate endpoints. OS chain building may retrieve intermediates even with revocation disabled.'}
        [pscustomobject]@{Check='HTTP headers / cookies / compression';Status='Partial';Explanation='One HTTP/1.1 HEAD request to the supplied path, no redirects or authentication. Missing header observations are contextual. Response headers are capped at 64 KiB and any incomplete response is marked.'}
        [pscustomobject]@{Check='STARTTLS';Status='Partial';Explanation='SMTP, IMAP, POP3, FTP and PostgreSQL upgrades. LDAP, XMPP, NNTP, MySQL, IRC, LMTP, Telnet and Sieve are unsupported.'}
        [pscustomobject]@{Check='TLS extensions / compression / secure renegotiation';Status='Partial';Explanation='ServerHello extensions and selected compression only. Renegotiation support is observed from renegotiation_info; no renegotiation attempt or denial-of-service test is performed.'}
        [pscustomobject]@{Check='BEAST / SWEET32 / FREAK / LOGJAM / POODLE / LUCKY13';Status='IndicatorsOnly';Explanation='Protocol/cipher prerequisites only. No attack execution, oracle test, DH prime analysis or patch verification. CBC or SSLv2 support alone does not confirm a named vulnerability.'}
        [pscustomobject]@{Check='Heartbleed / CCS injection / ROBOT / Ticketbleed / Winshock / DROWN / STARTTLS injection';Status='Unsupported';Explanation='Specialized vulnerability probes and cross-endpoint correlation are not implemented. No vulnerable-memory reads or exploit attempts.'}
        [pscustomobject]@{Check='TLS_FALLBACK_SCSV';Status='Unsupported';Explanation='No fallback-mitigation verdict. A dedicated controlled downgrade probe and alert interpretation are required.'}
        [pscustomobject]@{Check='Session resumption / OCSP stapling / SCT / CAA / client simulation / GREASE / ALPN / NPN';Status='Unsupported';Explanation='No browser fingerprint simulation, full encrypted extension parsing, DNS policy analysis, session replay or protocol-tolerance probes.'}
    )
}

function Add-TlsFinding {
    param([string]$Severity,[string]$Title,[string]$Status,[string]$Explanation,$Evidence,[string]$Recommendation,[string]$Command)
    $script:TlsFindings.Add([pscustomobject]@{Severity=$Severity;Finding=$Title;Status=$Status;Explanation=$Explanation;Command=$Command;Evidence=$Evidence;Recommendation=$Recommendation})
}

function Get-TlsCertificateDetails {
    param($Session)
    if (-not $Session.CertificateBase64) {return $null}
    $Cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[Convert]::FromBase64String($Session.CertificateBase64))
    try {
        $KeySize=$null;$KeyAlgorithm=$Cert.PublicKey.Oid.FriendlyName
        if ($Cert.PublicKey.Oid.Value -eq '1.2.840.113549.1.1.1') {
            $Key=[Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Cert)
        } elseif ($Cert.PublicKey.Oid.Value -eq '1.2.840.10045.2.1') {
            $Key=[Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Cert)
        } else {$Key=$null}
        if ($Key) {try {$KeySize=$Key.KeySize} finally {$Key.Dispose()}}
        $Extensions=@($Cert.Extensions | ForEach-Object {[pscustomobject]@{Oid=$_.Oid.Value;Name=$_.Oid.FriendlyName;Critical=$_.Critical;Text=$_.Format($true);RawBase64=[Convert]::ToBase64String($_.RawData)}})
        $Sha=[Security.Cryptography.SHA256]::Create()
        try {$Fingerprint=[BitConverter]::ToString($Sha.ComputeHash($Cert.RawData)).Replace('-','')} finally {$Sha.Dispose()}
        [pscustomobject]@{Subject=$Cert.Subject;Issuer=$Cert.Issuer;SerialNumber=$Cert.SerialNumber;NotBeforeUtc=$Cert.NotBefore.ToUniversalTime().ToString('o');NotAfterUtc=$Cert.NotAfter.ToUniversalTime().ToString('o');DaysRemaining=[Math]::Floor(($Cert.NotAfter.ToUniversalTime()-[datetime]::UtcNow).TotalDays);SignatureAlgorithm=$Cert.SignatureAlgorithm.FriendlyName;SignatureOid=$Cert.SignatureAlgorithm.Value;KeyAlgorithm=$KeyAlgorithm;KeyAlgorithmOid=$Cert.PublicKey.Oid.Value;KeyBits=$KeySize;Sha256=$Fingerprint;SubjectAlternativeName=(@($Extensions | Where-Object Oid -eq '2.5.29.17').Text -join "`n");Extensions=$Extensions;DerBase64=$Session.CertificateBase64;CertificateValid=$Session.CertificateValid;PolicyErrors=$Session.PolicyErrors;ChainStatus=$Session.ChainStatus;ChainCertificates=$Session.ChainCertificates}
    } finally {$Cert.Dispose()}
}

function Get-TlsHttpAnalysis {
    param([string]$Response,[bool]$Incomplete)
    $Lines=$Response -split '\r\n';$Headers=@()
    foreach ($Line in $Lines | Select-Object -Skip 1) {if (-not $Line) {break};if ($Line -match '^([^:\s]+):[ \t]*(.*)$') {$Headers+=[pscustomobject]@{Name=$Matches[1];Value=$Matches[2]}}}
    $Cookies=@($Headers | Where-Object Name -eq 'Set-Cookie' | ForEach-Object {[pscustomobject]@{Raw=$_.Value;Secure=[bool]($_.Value -match '(?i)(?:^|;)\s*Secure\s*(?:;|$)');HttpOnly=[bool]($_.Value -match '(?i)(?:^|;)\s*HttpOnly\s*(?:;|$)');SameSite=if($_.Value -match '(?i)(?:^|;)\s*SameSite=([^;]+)'){$Matches[1]}else{''}}})
    $Hsts=(@($Headers | Where-Object Name -eq 'Strict-Transport-Security').Value -join ', ')
    $HstsValid=$false;$MaxAge=$null
    if ($Hsts -match '(?i)(?:^|;)\s*max-age\s*=\s*([0-9]+)\s*(?:;|$)') {$ParsedAge=[decimal]0;if([decimal]::TryParse($Matches[1],[ref]$ParsedAge)){$MaxAge=$ParsedAge;$HstsValid=$MaxAge -gt 0}}
    [pscustomobject]@{StatusLine=$Lines[0];IsHttp=[bool]($Lines[0] -match '^HTTP/1\.[01] [0-9]{3}');Incomplete=$Incomplete;Headers=$Headers;Cookies=$Cookies;Hsts=$Hsts;HstsMaxAge=$MaxAge;HstsEnabled=$HstsValid;ContentEncoding=(@($Headers | Where-Object Name -eq 'Content-Encoding').Value -join ', ');RawResponse=$Response}
}

function Add-TlsTextField {
    param([Text.StringBuilder]$Builder,[string]$Label,$Value,[int]$Width=30)
    $Text=if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {'not collected'} else {[string]$Value}
    $Lines=[regex]::Split($Text,'\r\n|\n|\r')
    [void]$Builder.AppendLine(' '+$Label.PadRight($Width)+' '+$Lines[0])
    for ($i=1;$i -lt $Lines.Count;$i++) {[void]$Builder.AppendLine((' '*($Width+2))+$Lines[$i])}
}

function Get-TlsTextProbeStatus {
    param($Row)
    if ($null -eq $Row) {return 'not tested (check omitted or no result)'}
    if ($Row.Selected) {
        if ($Row.Status -eq 'HelloRetryRequestObserved') {return 'offered (HelloRetryRequest observed; selection only)'}
        return 'offered (ServerHello observed; selection only)'
    }
    if ($Row.Status -eq 'NotTested') {return 'not tested: '+[string]$Row.Probe.Error}
    if ($Row.Status -eq 'AlertReceived') {return 'not selected (TLS alert: '+(@($Row.Probe.Alerts) -join '; ')+'); inconclusive'}
    return 'inconclusive: '+$(if($Row.Probe.Error){[string]$Row.Probe.Error}else{[string]$Row.Status})
}

function Get-TlsTextCipherSummary {
    param([object[]]$Rows)
    if (@($Rows).Count -eq 0) {return 'not tested (no matching catalog probes)'}
    $Selected=@($Rows | Where-Object Selected)
    $Unknown=@($Rows | Where-Object {$_.Status -in @('Inconclusive','NotTested','NotNegotiated')})
    if ($Selected.Count) {
        $Names=@($Selected | ForEach-Object {$_.Cipher.Name} | Sort-Object -Unique)
        return 'offered (selection observed): '+$Names.Count+' catalog suite(s); '+$Unknown.Count+' incomplete probe(s)'+"`n"+($Names -join "`n")
    }
    return 'no selection observed in '+@($Rows).Count+' catalog probe(s); '+$Unknown.Count+' incomplete (not a security pass)'
}

function ConvertTo-TlsTextTimestamp {
    param($Value)
    if ($null -eq $Value) {return 'not recorded'}
    try {
        if ($Value -is [datetime] -or $Value -is [DateTimeOffset]) {$Date=[DateTimeOffset]$Value}
        else {$Date=[DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)}
        return $Date.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'",[Globalization.CultureInfo]::InvariantCulture)
    } catch {return [string]$Value}
}

function New-TlsReportText {
    param($Report,[string]$EvidenceJson='')
    $Builder=New-Object Text.StringBuilder
    $Metadata=$Report.Metadata;$Endpoint=$Metadata.Target
    $Protocols=@($Report.Protocols | Where-Object {$null -ne $_})
    $Ciphers=@($Report.Ciphers | Where-Object {$null -ne $_})
    $Selected=@($Ciphers | Where-Object Selected)
    $Peer=$Endpoint.ConnectAddress+':'+$Endpoint.Port+' ('+$Endpoint.ServerName+')'
    [void]$Builder.AppendLine('#'*69)
    [void]$Builder.AppendLine('  testssl.ps1 version '+$Metadata.Version+' -- Native Windows TLS/SSL audit')
    [void]$Builder.AppendLine('  Independent implementation inspired by https://github.com/testssl/testssl.sh')
    [void]$Builder.AppendLine('  Output layout follows reference/testssl_output.txt; no template scan results are reused.')
    [void]$Builder.AppendLine('  Selection is not authentication. Unknown/unsupported checks are not security passes.')
    [void]$Builder.AppendLine('#'*69)
    [void]$Builder.AppendLine('')
    Add-TlsTextField $Builder 'Using' ('native .NET sockets / Windows SslStream; PowerShell '+$Metadata.PowerShellVersion)
    Add-TlsTextField $Builder 'Cipher catalog' ([string]$Metadata.CipherCatalogCount+' suites (limited catalog; no OpenSSL engine)')
    Add-TlsTextField $Builder 'Address scope' $Metadata.AddressScope
    Add-TlsTextField $Builder 'Testing endpoint' $Peer
    [void]$Builder.AppendLine('-'*71)
    [void]$Builder.AppendLine(' Start '+(ConvertTo-TlsTextTimestamp $Metadata.StartedUtc)+' -->> '+$Peer+' <<--')
    [void]$Builder.AppendLine('')
    $Others=@($Endpoint.ResolvedAddresses | Where-Object {$_ -ne $Endpoint.ConnectAddress})
    Add-TlsTextField $Builder 'Further IP addresses' $(if($Others.Count){($Others -join ' ')+' (not scanned)'}else{'none recorded'})
    Add-TlsTextField $Builder 'SNI / validation name' $Endpoint.ServerName
    Add-TlsTextField $Builder 'rDNS' 'not tested'
    $Service=if ($Report.Http -and $Report.Http.IsHttp) {'HTTP (HTTP/1.x response observed)'} elseif ($Metadata.StartTls -ne 'none') {$Metadata.StartTls.ToUpperInvariant()+' STARTTLS (see upgrade transcripts)'} else {'not established'}
    Add-TlsTextField $Builder 'Service detected' $Service
    Add-TlsTextField $Builder 'Checks requested' (@($Metadata.ChecksRequested) -join ', ')

    [void]$Builder.AppendLine("`n Testing protocols via native sockets`n")
    foreach ($Definition in @(@{Name='SSLv2';Version=2},@{Name='SSLv3';Version=768},@{Name='TLS 1';Version=769},@{Name='TLS 1.1';Version=770},@{Name='TLS 1.2';Version=771},@{Name='TLS 1.3';Version=772})) {
        $Row=@($Protocols | Where-Object Version -eq $Definition.Version | Select-Object -First 1)
        Add-TlsTextField $Builder $Definition.Name (Get-TlsTextProbeStatus $(if($Row.Count){$Row[0]}else{$null})) 12
    }
    Add-TlsTextField $Builder 'NPN/SPDY' 'unsupported (no NPN probe)' 12
    Add-TlsTextField $Builder 'ALPN/HTTP2' 'unsupported (HTTP uses HTTP/1.1)' 12

    [void]$Builder.AppendLine("`n Testing cipher categories (catalog scope only)`n")
    foreach ($Category in @(
        @{Label='NULL ciphers (no encryption)';Pattern='^NULL encryption$'},
        @{Label='Anonymous ciphers (no authentication)';Pattern='^Anonymous authentication$'},
        @{Label='Export ciphers';Pattern='^EXPORT'},
        @{Label='DES / RC4 ciphers';Pattern='^(DES|RC4)$'},
        @{Label='Triple DES / 64-bit block ciphers';Pattern='3DES'},
        @{Label='Obsoleted CBC ciphers';Pattern='^CBC'},
        @{Label='AEAD with static RSA (no FS)';Pattern='^AEAD / static RSA$'},
        @{Label='Authenticated AEAD with FS indicators';Pattern='^AEAD$'},
        @{Label='TLS 1.3 AEAD selection';Pattern='^TLS 1.3 AEAD$'}
    )) {
        $CategoryRows=@($Ciphers | Where-Object {$_.Cipher.Category -match $Category.Pattern})
        Add-TlsTextField $Builder $Category.Label (Get-TlsTextCipherSummary $CategoryRows) 49
    }

    [void]$Builder.AppendLine("`n Testing server's cipher preferences`n")
    [void]$Builder.AppendLine(' Hexcode  Cipher Suite Name (IANA/RFC)                           Category                    FS indicator')
    [void]$Builder.AppendLine('-'*125)
    foreach ($Version in @(2,768,769,770,771,772)) {
        $Name=switch($Version){2{'SSLv2'};768{'SSLv3'};769{'TLSv1'};770{'TLSv1.1'};771{'TLSv1.2'};772{'TLSv1.3'}}
        $Preference=@($Report.Preference | Where-Object ProtocolVersion -eq $Version | Select-Object -First 1)
        [void]$Builder.AppendLine($Name+$(if($Preference.Count){' ('+$Preference[0].Status+'; tested pair only)'}else{' (complete preference ranking not tested)'}))
        $Rows=@($Selected | Where-Object ProtocolVersion -eq $Version)
        foreach ($Row in $Rows) {[void]$Builder.AppendLine((' x{0,-6} {1,-54} {2,-27} {3}' -f $Row.Cipher.Hex.ToLowerInvariant(),$Row.Cipher.Name,$Row.Cipher.Category,$Row.Cipher.ForwardSecrecy))}
        if (-not $Rows.Count) {[void]$Builder.AppendLine(' - no catalog suite selection observed; absence does not prove suites are disabled')}
    }
    [void]$Builder.AppendLine(' Listed suites follow probe/catalog order, not an inferred complete server ranking.')
    foreach ($Preference in @($Report.Preference | Where-Object {$null -ne $_})) {
        Add-TlsTextField $Builder ('Preference 0x{0:X4}' -f $Preference.ProtocolVersion) ($Preference.Status+'; '+$Preference.Explanation)
        foreach ($Probe in @($Preference.Probes | Where-Object {$null -ne $_})) {Add-TlsTextField $Builder 'Pair selection' ('0x{0:X4}; {1}' -f $Probe.SelectedCipher,$Probe.Outcome)}
    }

    [void]$Builder.AppendLine("`n Testing robust forward secrecy (FS) -- suite indicators only`n")
    $Fs=@($Selected | Where-Object {$_.Cipher.ForwardSecrecy -eq 'Yes' -and $_.Cipher.Severity -notin @('Critical','High')} | ForEach-Object {$_.Cipher.Name} | Sort-Object -Unique)
    Add-TlsTextField $Builder 'FS suite indicators' $(if($Fs.Count){$Fs -join "`n"}else{'none observed in the tested catalog; not a security pass'})
    Add-TlsTextField $Builder 'Actual key exchange' 'not established by raw selection probes; DH parameter strength not tested'
    Add-TlsTextField $Builder 'KEMs offered' 'unsupported (no KEM enumeration)'
    Add-TlsTextField $Builder 'Elliptic curves offered' 'unsupported (no full group enumeration; HRR group bytes appear in the evidence)'
    Add-TlsTextField $Builder 'TLS signature algorithms' 'unsupported (no server signature-algorithm enumeration)'

    [void]$Builder.AppendLine("`n Testing server defaults (Server Hello)`n")
    $ExtensionLines=@($Report.Extensions | ForEach-Object {$Protocol=$_.Protocol;foreach($Extension in @($_.Extensions)){if($null -ne $Extension){$Protocol+': '+$Extension.Name+'/#'+$Extension.Id+' = '+$Extension.Hex}}})
    Add-TlsTextField $Builder 'TLS extensions observed' $(if($ExtensionLines.Count){$ExtensionLines -join "`n"}else{'none collected'})
    Add-TlsTextField $Builder 'Session Ticket lifetime hint' 'not tested'
    $Ids=@($Protocols | Where-Object Selected | ForEach-Object {$_.Protocol+': '+$_.Probe.SessionIdLength+' byte(s)'})
    Add-TlsTextField $Builder 'Session IDs observed' $(if($Ids.Count){($Ids -join '; ')+'; not proof of resumption support'}else{'none collected'})
    Add-TlsTextField $Builder 'Session Resumption' 'unsupported (no ticket/ID replay)'
    Add-TlsTextField $Builder 'TLS clock skew' 'not tested'
    Add-TlsTextField $Builder 'Certificate Compression' 'not tested'
    Add-TlsTextField $Builder 'Client Authentication' 'not assessed (no client certificate supplied)'
    $Native=$Report.NativeSession
    if ($Native) {
        Add-TlsTextField $Builder 'Windows TLS handshake' $(if($Native.Success){'completed; certificate trust is reported separately'}else{'inconclusive: '+$Native.Error})
        Add-TlsTextField $Builder 'Windows negotiated protocol' $Native.Protocol
        Add-TlsTextField $Builder 'Windows negotiated cipher' $(if($Native.CipherSuite){$Native.CipherSuite}else{$Native.CipherAlgorithm+' / '+$Native.CipherStrength+' bits (exact suite unavailable from this runtime)'})
    } else {Add-TlsTextField $Builder 'Windows TLS handshake' 'not tested (Certificate/Http checks omitted)'}

    [void]$Builder.AppendLine("`n  Server Certificate #1 (one native-session leaf; alternate certificates not enumerated)")
    $Cert=$Report.Certificate
    if ($Cert) {
        Add-TlsTextField $Builder 'Signature Algorithm' ($Cert.SignatureAlgorithm+' / '+$Cert.SignatureOid)
        Add-TlsTextField $Builder 'Server key size' ($Cert.KeyAlgorithm+' '+$Cert.KeyBits+' bits')
        Add-TlsTextField $Builder 'Server key usage' (@($Cert.Extensions | Where-Object Oid -eq '2.5.29.15').Text -join "`n")
        Add-TlsTextField $Builder 'Server extended key usage' (@($Cert.Extensions | Where-Object Oid -eq '2.5.29.37').Text -join "`n")
        Add-TlsTextField $Builder 'Serial' $Cert.SerialNumber
        Add-TlsTextField $Builder 'Fingerprint SHA256' $Cert.Sha256
        Add-TlsTextField $Builder 'Subject (DN)' $Cert.Subject
        Add-TlsTextField $Builder 'subjectAltName (SAN)' $Cert.SubjectAlternativeName
        Add-TlsTextField $Builder 'Windows certificate validation' $(if($Cert.CertificateValid){'no validation errors reported by Windows'}else{'FAILED: '+$Cert.PolicyErrors})
        Add-TlsTextField $Builder 'Chain status' $(if(@($Cert.ChainStatus).Count){@($Cert.ChainStatus) -join "`n"}else{'no chain status errors recorded; see validation result'})
        Add-TlsTextField $Builder 'Certificate Validity (UTC)' ([string]$Cert.DaysRemaining+' day(s) remaining ('+$Cert.NotBeforeUtc+' --> '+$Cert.NotAfterUtc+')')
        Add-TlsTextField $Builder 'Issuer' $Cert.Issuer
        Add-TlsTextField $Builder 'Windows chain certificates' (@($Cert.ChainCertificates).Count.ToString()+' (may include local/downloaded certificates)')
    } else {Add-TlsTextField $Builder 'Certificate data' 'not collected; check requested groups and collection errors'}
    Add-TlsTextField $Builder 'Revocation checking' $(if($Metadata.RevocationRequested){'requested via Windows policy; see chain validation evidence'}else{'not requested; no revocation verdict'})
    foreach ($Label in @('EV certificate','OCSP stapling / must staple','DNS CAA RR','Certificate Transparency')) {Add-TlsTextField $Builder $Label 'unsupported'}

    [void]$Builder.AppendLine("`n Testing HTTP header response @ `"$($Endpoint.PathAndQuery)`"`n")
    $Http=$Report.Http
    if ($Http -and $Http.IsHttp) {
        Add-TlsTextField $Builder 'HTTP Status Code' $Http.StatusLine
        Add-TlsTextField $Builder 'Header capture' $(if($Http.Incomplete){'INCOMPLETE -- missing-header verdicts not made'}else{'complete captured HTTP/1.x header block'})
        Add-TlsTextField $Builder 'Strict Transport Security' $(if($Http.Hsts){$Http.Hsts}else{'no header observed'+$(if($Http.Incomplete){' in partial capture'}else{' on tested response'})})
        Add-TlsTextField $Builder 'Server banner' (@($Http.Headers | Where-Object Name -eq 'Server').Value -join "`n")
        Add-TlsTextField $Builder 'Application banner' (@($Http.Headers | Where-Object Name -in @('X-Powered-By','X-AspNet-Version')).Value -join "`n")
        $Cookies=@($Http.Cookies | Where-Object {$null -ne $_});$Secure=@($Cookies | Where-Object Secure).Count;$HttpOnly=@($Cookies | Where-Object HttpOnly).Count
        Add-TlsTextField $Builder 'Cookie(s)' ($Cookies.Count.ToString()+' captured: '+$Secure+'/'+$Cookies.Count+' Secure, '+$HttpOnly+'/'+$Cookies.Count+' HttpOnly')
        $SecurityHeaders=@($Http.Headers | Where-Object Name -in @('Content-Security-Policy','Content-Security-Policy-Report-Only','X-Frame-Options','X-Content-Type-Options','X-XSS-Protection','Referrer-Policy','Permissions-Policy','Cache-Control') | ForEach-Object {$_.Name+': '+$_.Value})
        Add-TlsTextField $Builder 'Security headers' ($SecurityHeaders -join "`n")
        Add-TlsTextField $Builder 'Content-Encoding' $Http.ContentEncoding
        Add-TlsTextField $Builder 'HTTP scope' 'one HEAD response; no redirect traversal or body vulnerability analysis'
    } else {Add-TlsTextField $Builder 'HTTP response' $(if($Metadata.StartTls -ne 'none'){'not applicable to selected STARTTLS service'}else{'not collected or not identified as HTTP/1.x; see errors and evidence'})}

    [void]$Builder.AppendLine("`n Testing vulnerabilities (observations / prerequisites; no exploit verdicts)`n")
    foreach ($Label in @('Heartbleed (CVE-2014-0160)','CCS (CVE-2014-0224)','Ticketbleed (CVE-2016-9244)','ROBOT','STARTTLS injection','Winshock (CVE-2014-6321)','TLS_FALLBACK_SCSV')) {Add-TlsTextField $Builder $Label 'unsupported -- not tested' 41}
    $Compression=@($Report.Extensions | Where-Object {$_.Compression -gt 0})
    Add-TlsTextField $Builder 'CRIME / TLS compression' $(if($Compression.Count){'TLS compression selected; prerequisite only'}elseif(@($Report.Extensions).Count){'no compression selected in observed hellos; no attack probe'}else{'not tested'}) 41
    Add-TlsTextField $Builder 'BREACH / HTTP compression' $(if($Http -and $Http.ContentEncoding -match '(?i)gzip|deflate|br'){'HTTP compression observed; secrets/reflected input not assessed'}else{'not established; HEAD does not assess compressed body contents'}) 41
    Add-TlsTextField $Builder 'Secure Renegotiation' $(if(@($Report.Extensions | Where-Object SecureRenegotiationExtensionPresent).Count){'renegotiation_info extension observed; no renegotiation attempt'}else{'not established; renegotiation attempt unsupported'}) 41
    Add-TlsTextField $Builder 'DROWN (CVE-2016-0800)' 'unsupported -- SSLv2 selection alone is not a DROWN assessment' 41
    foreach ($Indicator in @(
        @{Label='POODLE / SSLv3 CBC';Rows=@($Selected | Where-Object {$_.ProtocolVersion -eq 768 -and $_.Cipher.Name -match '_CBC_'})},
        @{Label='SWEET32 / 64-bit block ciphers';Rows=@($Selected | Where-Object {$_.Cipher.Category -match '3DES'})},
        @{Label='FREAK / RSA EXPORT';Rows=@($Selected | Where-Object {$_.Cipher.Name -like 'TLS_RSA_EXPORT*'})},
        @{Label='LOGJAM / DH EXPORT';Rows=@($Selected | Where-Object {$_.Cipher.Category -eq 'EXPORT DH'})},
        @{Label='BEAST / SSLv3 or TLS 1 CBC';Rows=@($Selected | Where-Object {$_.ProtocolVersion -in @(768,769) -and $_.Cipher.Name -match '_CBC_'})},
        @{Label='LUCKY13 / TLS CBC';Rows=@($Selected | Where-Object {$_.ProtocolVersion -in @(769,770,771) -and $_.Cipher.Name -match '_CBC_'})},
        @{Label='RC4 cipher selection';Rows=@($Selected | Where-Object {$_.Cipher.Category -match 'RC4'})}
    )) {Add-TlsTextField $Builder $Indicator.Label $(if($Indicator.Rows.Count){'catalog selection observed (prerequisite only): '+(@($Indicator.Rows | ForEach-Object {$_.Cipher.Name} | Sort-Object -Unique) -join ', ')}else{'not established by catalog selections; no attack probe'}) 41}
    Add-TlsTextField $Builder 'DH group/prime strength' 'unsupported -- no parameter or common-prime analysis' 41

    [void]$Builder.AppendLine("`n Security findings (severity order)`n")
    $Ranks=@{Critical=0;High=1;Medium=2;Low=3;Informational=4}
    $Findings=@($Report.Findings | Sort-Object @{Expression={$Ranks[$_.Severity]}},Finding)
    foreach ($Finding in $Findings) {
        [void]$Builder.AppendLine(' ['+$Finding.Severity+'] '+$Finding.Finding+' -- '+$Finding.Status)
        Add-TlsTextField $Builder 'Explanation' $Finding.Explanation
        Add-TlsTextField $Builder 'Recommendation' $Finding.Recommendation
        Add-TlsTextField $Builder 'Repeatable command' $Finding.Command
        [void]$Builder.AppendLine('')
    }
    if (-not $Findings.Count) {[void]$Builder.AppendLine(' No findings recorded. This is not an all-clear; inspect unknown results and coverage.')}
    $Summary=$Report.SeveritySummary
    Add-TlsTextField $Builder 'Severity totals' ('Critical: '+$Summary.Critical+'; High: '+$Summary.High+'; Medium: '+$Summary.Medium+'; Low: '+$Summary.Low+'; Informational: '+$Summary.Informational)

    [void]$Builder.AppendLine("`n Running client simulations`n")
    Add-TlsTextField $Builder 'Browser/client simulation' 'unsupported -- no client fingerprint simulation performed'
    [void]$Builder.AppendLine("`n Rating (experimental)`n")
    Add-TlsTextField $Builder 'SSL Labs rating / score' 'unsupported -- no rating model implemented'
    Add-TlsTextField $Builder 'Overall Grade' 'not assigned; severity counts are not an SSL Labs grade'
    [void]$Builder.AppendLine("`n Coverage and collection errors`n")
    foreach ($Coverage in @($Report.Coverage)) {Add-TlsTextField $Builder $Coverage.Check ($Coverage.Status+' -- '+$Coverage.Explanation) 49}
    foreach ($ErrorRow in @($Report.Errors | Where-Object {$null -ne $_})) {Add-TlsTextField $Builder $ErrorRow.Check ($ErrorRow.Status+' -- '+$ErrorRow.Error) 30}
    Add-TlsTextField $Builder 'Overall deadline reached' $Metadata.DeadlineReached
    [void]$Builder.AppendLine("`n Full selected evidence (JSON appendix -- commands, captured responses and errors)`n")
    if ([string]::IsNullOrWhiteSpace($EvidenceJson)) {$EvidenceJson=ConvertTo-Json -InputObject $Report -Depth 40 -WarningAction Stop}
    [void]$Builder.AppendLine($EvidenceJson)
    $Duration='unknown'
    try {
        $Completed=if ($Metadata.CompletedUtc -is [datetime] -or $Metadata.CompletedUtc -is [DateTimeOffset]) {[DateTimeOffset]$Metadata.CompletedUtc} else {[DateTimeOffset]::Parse([string]$Metadata.CompletedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)}
        $Started=if ($Metadata.StartedUtc -is [datetime] -or $Metadata.StartedUtc -is [DateTimeOffset]) {[DateTimeOffset]$Metadata.StartedUtc} else {[DateTimeOffset]::Parse([string]$Metadata.StartedUtc,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal)}
        $Duration=[Math]::Max([double]0,($Completed-$Started).TotalSeconds).ToString('0.0',[Globalization.CultureInfo]::InvariantCulture)
    } catch {}
    [void]$Builder.AppendLine('')
    [void]$Builder.AppendLine(' Done '+(ConvertTo-TlsTextTimestamp $Metadata.CompletedUtc)+' [ '+$Duration+'s ] -->> '+$Peer+' <<--')
    return $Builder.ToString()
}

function New-TlsReportHtml {
    param($Report)
    $Ranks=@{Critical=0;High=1;Medium=2;Low=3;Informational=4};$Rows=New-Object Text.StringBuilder
    foreach ($Finding in @($Report.Findings | Sort-Object @{Expression={$Ranks[$_.Severity]}},Finding)) {
        $Evidence=ConvertTo-Json -InputObject $Finding.Evidence -Depth 40 -WarningAction Stop
        [void]$Rows.Append('<tr data-rank="'+$Ranks[$Finding.Severity]+'"><td class="risk">'+(ConvertTo-TlsHtml $Finding.Severity)+'</td><td>'+(ConvertTo-TlsHtml $Finding.Finding)+'</td><td>'+(ConvertTo-TlsHtml $Finding.Status)+'</td><td>'+(ConvertTo-TlsHtml $Finding.Explanation)+'</td><td><details><summary>Command and full saved evidence</summary><pre><code><span class="cmd">PS&gt; '+(ConvertTo-TlsHtml $Finding.Command)+'</span>'+"`n"+(ConvertTo-TlsHtml $Evidence)+'</code></pre></details></td><td>'+(ConvertTo-TlsHtml $Finding.Recommendation)+'</td></tr>')
    }
    $Sections=New-Object Text.StringBuilder
    foreach ($Key in @('Metadata','Coverage','Protocols','Ciphers','Preference','Certificate','NativeSession','Extensions','Http','Errors')) {
        $Value=ConvertTo-Json -InputObject $Report[$Key] -Depth 40 -WarningAction Stop
        [void]$Sections.Append('<details><summary>'+(ConvertTo-TlsHtml $Key)+'</summary><pre><code>'+(ConvertTo-TlsHtml $Value)+'</code></pre></details>')
    }
    $TargetText=ConvertTo-TlsHtml ($Report.Metadata.Target.Host+':'+$Report.Metadata.Target.Port)
    $Script=@'
<script>(()=>{const t=document.querySelector('table'),b=t.tBodies[0],h=Array.from(t.tHead.rows[0].cells);let col=0,up=true;const rows=()=>Array.from(b.rows);h.forEach((x,i)=>x.querySelector('button').onclick=()=>{up=col===i?!up:true;col=i;rows().sort((a,c)=>{const n=i===0?Number(a.dataset.rank)-Number(c.dataset.rank):a.cells[i].textContent.localeCompare(c.cells[i].textContent,undefined,{numeric:true});return up?n:-n}).forEach(r=>b.appendChild(r));h.forEach((q,j)=>q.setAttribute('aria-sort',j===i?(up?'ascending':'descending'):'none'))});document.querySelector('input').oninput=e=>rows().forEach(r=>r.hidden=!r.textContent.toLowerCase().includes(e.target.value.toLowerCase()));document.getElementById('expand').onclick=()=>document.querySelectorAll('details').forEach(d=>d.open=true);document.getElementById('collapse').onclick=()=>document.querySelectorAll('details').forEach(d=>d.open=false)})();</script>
'@
    return @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>TLS audit - $TargetText</title><style>body{font:14px/1.5 'Segoe UI',sans-serif;background:#f2f5f9;color:#172b4d;margin:24px}details{background:white;padding:14px;margin:12px 0;border:1px solid #dbe3ed;border-radius:6px}summary{cursor:pointer;font-weight:bold}pre{background:#112238;color:#e3edf8;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.6 Consolas,monospace}.cmd{color:#a5e9c5}.scroll{overflow:auto}table{border-collapse:collapse;width:100%}td,th{padding:12px;border-bottom:1px solid #dbe3ed;text-align:left;vertical-align:top}th{background:#eaf0f8}button,input{padding:7px;font:inherit}th button{border:0;background:transparent;cursor:pointer}th[aria-sort=ascending] button:after{content:' ▲'}th[aria-sort=descending] button:after{content:' ▼'}tr[data-rank="0"] .risk,tr[data-rank="1"] .risk{color:#a31525;font-weight:bold}td:nth-child(4){min-width:220px}td:nth-child(5){min-width:300px}td:last-child{min-width:200px}</style></head>
<body><h1>Native TLS/SSL audit: $TargetText</h1><p>Selection probes and vulnerability prerequisites are observations, not proof of exploitability. Unsupported checks and incomplete coverage are listed below. Certificate validation uses the scanner machine's Windows trust store.</p><button id="expand">Expand sections</button> <button id="collapse">Collapse sections</button>
<details open><summary>Findings ($(@($Report.Findings).Count))</summary><p><label>Filter <input type="search"></label></p><div class="scroll"><table><thead><tr><th aria-sort="ascending"><button>Severity</button></th><th><button>Finding</button></th><th><button>Status</button></th><th><button>Explanation</button></th><th><button>Evidence</button></th><th><button>Recommendation</button></th></tr></thead><tbody>$Rows</tbody></table></div></details>$Sections$Script</body></html>
"@
}

function Invoke-NativeTlsAudit {
    param($Endpoint,[string]$Upgrade,[string[]]$SelectedChecks,[int]$ProbeTimeout,[int]$ScanTimeout,[bool]$Revocation,[string]$Destination,[string]$ScriptPath)
    Initialize-NativeTlsProbe
    $Watch=[Diagnostics.Stopwatch]::StartNew();$Started=[datetime]::UtcNow
    $script:TlsFindings=New-Object 'System.Collections.Generic.List[object]'
    $Errors=New-Object 'System.Collections.Generic.List[object]'
    $Catalog=@(Get-TlsCipherCatalog);$ProtocolRows=New-Object 'System.Collections.Generic.List[object]';$CipherRows=New-Object 'System.Collections.Generic.List[object]';$Preferences=New-Object 'System.Collections.Generic.List[object]'
    $BaseCommand='& '+(ConvertTo-TlsLiteral $ScriptPath)+' -Target '+(ConvertTo-TlsLiteral ('https://'+$Endpoint.HostHeader+$Endpoint.PathAndQuery))+' -ServerName '+(ConvertTo-TlsLiteral $Endpoint.ServerName)+' -ConnectAddress '+(ConvertTo-TlsLiteral $Endpoint.ConnectAddress)+' -StartTls '+$Upgrade+' -TimeoutSeconds '+$ProbeTimeout+' -ScanTimeoutSeconds '+$ScanTimeout
    if ($Revocation) {$BaseCommand+=' -CheckRevocation'}
    # Commands rerun a check group and write new reports; they are not stored scripts to execute.
    $ProtocolCommand=$BaseCommand+' -Checks Protocols'
    $RawNeeded=@($SelectedChecks | Where-Object {$_ -in @('Protocols','Ciphers','Extensions','Preference')}).Count -gt 0
    $Observed=@()
    if ($RawNeeded) {
        foreach ($Definition in @(@{Name='SSLv2';Version=2;Severity='Critical'},@{Name='SSLv3';Version=768;Severity='High'},@{Name='TLS 1.0';Version=769;Severity='High'},@{Name='TLS 1.1';Version=770;Severity='Medium'},@{Name='TLS 1.2';Version=771;Severity='Informational'},@{Name='TLS 1.3';Version=772;Severity='Informational'})) {
            Write-Host ('[+] '+$Definition.Name+' selection probe')
            $Budget=[Math]::Min($ProbeTimeout*1000,[Math]::Max(0,$ScanTimeout*1000-$Watch.ElapsedMilliseconds))
            if ($Budget -le 0) {$Result=[pscustomobject]@{Outcome='NotTested';Error='Overall scan deadline reached'}}
            elseif ($Definition.Version -eq 2) {$Result=[WindowsTlsAudit.V1.Scanner]::ProbeSsl2($Endpoint.ConnectAddress,$Endpoint.Port,$Upgrade,[int]$Budget)}
            else {
                $Suites=if ($Definition.Version -eq 772) {@(0x1301,0x1302,0x1303)} else {@($Catalog | Where-Object {$_.Id -lt 0x1301 -or $_.Id -gt 0x1303} | ForEach-Object {$_.Id})}
                $Result=[WindowsTlsAudit.V1.Scanner]::Probe($Endpoint.ConnectAddress,$Endpoint.Port,$Endpoint.ServerName,$Upgrade,$Definition.Version,[int[]]$Suites,[int]$Budget,$false)
            }
            $Selected=$Result.Outcome -in @('ServerHelloObserved','HelloRetryRequestObserved')
            $Row=[pscustomobject]@{Protocol=$Definition.Name;Version=$Definition.Version;Status=$Result.Outcome;Selected=$Selected;Explanation='A matching ServerHello/HelloRetryRequest establishes protocol selection only. Failure, alert or timeout is inconclusive about complete server support; client offers, middleboxes and rate limiting can affect results.';Command=$ProtocolCommand;Probe=$Result}
            $ProtocolRows.Add($Row)
            if ($Selected) {
                $Observed+=$Definition.Version
                if ($Definition.Severity -ne 'Informational') {Add-TlsFinding $Definition.Severity ($Definition.Name+' selected by server') 'Observed' 'A deprecated protocol was selected for this raw ClientHello. No authenticated session or exploit was completed.' $Row 'Disable obsolete protocols after checking required clients.' $ProtocolCommand}
            } elseif ($Result.Outcome -in @('Inconclusive','NotTested')) {$Errors.Add([pscustomobject]@{Check=$Definition.Name;Status=$Result.Outcome;Error=$Result.Error})}
        }
    }
    if ('Ciphers' -in $SelectedChecks) {
        foreach ($Version in @($Observed | Where-Object {$_ -ge 768})) {
            $Candidates=@($Catalog | Where-Object {if ($Version -eq 772) {$_.Category -like 'TLS 1.3*'} else {$_.Category -notlike 'TLS 1.3*'}})
            foreach ($Cipher in $Candidates) {
                $Budget=[Math]::Min($ProbeTimeout*1000,[Math]::Max(0,$ScanTimeout*1000-$Watch.ElapsedMilliseconds))
                if ($Budget -le 0) {$Result=[pscustomobject]@{Outcome='NotTested';Error='Overall scan deadline reached'}}
                else {$Result=[WindowsTlsAudit.V1.Scanner]::Probe($Endpoint.ConnectAddress,$Endpoint.Port,$Endpoint.ServerName,$Upgrade,$Version,[int[]]@($Cipher.Id),[int]$Budget,$false)}
                $Selected=$Result.Outcome -in @('ServerHelloObserved','HelloRetryRequestObserved')
                $Row=[pscustomobject]@{ProtocolVersion=$Version;Cipher=$Cipher;Status=$Result.Outcome;Selected=$Selected;Probe=$Result}
                $CipherRows.Add($Row)
                if ($Selected -and $Cipher.Severity -ne 'Informational') {Add-TlsFinding $Cipher.Severity ($Cipher.Name+' selected / protocol 0x{0:X4}' -f $Version) 'Review' ('Server selected this offered suite. Category: '+$Cipher.Category+'. This is a configuration observation, not confirmation of BEAST, SWEET32, FREAK, LOGJAM, LUCKY13 or another attack.') $Row 'Prefer authenticated AEAD suites with ephemeral key exchange; evaluate compatibility before disabling suites.' ($BaseCommand+' -Checks Ciphers')}
            }
        }
        if (-not @($Observed | Where-Object {$_ -ge 768}).Count) {$Errors.Add([pscustomobject]@{Check='Ciphers';Status='NotTested';Error='No TLS/SSLv3 protocol selection was observed.'})}
    }
    if ('Preference' -in $SelectedChecks) {
        foreach ($Version in @($Observed | Where-Object {$_ -in @(771,772)})) {
            $Available=@($CipherRows | Where-Object {$_.ProtocolVersion -eq $Version -and $_.Selected} | ForEach-Object {$_.Cipher.Id})
            if ($Available.Count -lt 2) {$Preferences.Add([pscustomobject]@{ProtocolVersion=$Version;Status='NotTested';Explanation='At least two individually selected suites are required; include Ciphers in Checks.'});continue}
            $First=@($Available[0],$Available[1]);$Second=@($Available[1],$Available[0]);$Results=@()
            foreach ($Offer in @([pscustomobject]@{Suites=$First},[pscustomobject]@{Suites=$Second})) {
                $Budget=[Math]::Min($ProbeTimeout*1000,[Math]::Max(0,$ScanTimeout*1000-$Watch.ElapsedMilliseconds))
                if ($Budget -le 0) {$Results+=[pscustomobject]@{Outcome='NotTested';SelectedCipher=-1}} else {$Results+=[WindowsTlsAudit.V1.Scanner]::Probe($Endpoint.ConnectAddress,$Endpoint.Port,$Endpoint.ServerName,$Upgrade,$Version,[int[]]$Offer.Suites,[int]$Budget,$false)}
            }
            $Status=if (@($Results | Where-Object {$_.Outcome -notin @('ServerHelloObserved','HelloRetryRequestObserved')}).Count) {'Inconclusive'} elseif ($Results[0].SelectedCipher -eq $Results[1].SelectedCipher) {'ServerPreferenceObservedForPair'} else {'ClientOrderObservedForPair'}
            $Preferences.Add([pscustomobject]@{ProtocolVersion=$Version;Status=$Status;OfferedPairs=@($First,$Second);Probes=$Results;Explanation='Two reversed offers only; not a complete ranking or proof of stable policy across all endpoints.'})
        }
    }
    $Native=$null;$Certificate=$null;$Http=$null
    if (@($SelectedChecks | Where-Object {$_ -in @('Certificate','Http')}).Count) {
        $Budget=[Math]::Min($ProbeTimeout*1000,[Math]::Max(0,$ScanTimeout*1000-$Watch.ElapsedMilliseconds))
        $Request=if ('Http' -in $SelectedChecks -and $Upgrade -eq 'none') {'HEAD '+$Endpoint.PathAndQuery+" HTTP/1.1`r`nHost: "+$Endpoint.HostHeader+"`r`nUser-Agent: WindowsHostSecurityCheck-TLS/1.0`r`nAccept-Encoding: gzip, deflate, br`r`nConnection: close`r`n`r`n"} else {''}
        if ($Budget -gt 0) {$Native=[WindowsTlsAudit.V1.Scanner]::Session($Endpoint.ConnectAddress,$Endpoint.Port,$Endpoint.ServerName,$Upgrade,0,[int]$Budget,$Revocation,$Request)}
        else {$Native=[pscustomobject]@{Success=$false;Error='Overall scan deadline reached';CertificateBase64=''}}
        if ($Native.CertificateBase64) {
            $Certificate=Get-TlsCertificateDetails $Native
            if (-not $Certificate.CertificateValid) {Add-TlsFinding 'High' 'Certificate validation failed' 'Observed' 'Windows reported name, chain or certificate validation errors. Private CA trust and scanning identity can affect this result; the audit callback allowed collection on this connection only.' $Certificate 'Resolve hostname, validity and chain issues; verify intended internal trust anchors.' ($BaseCommand+' -Checks Certificate')}
            if ([datetime]::Parse($Certificate.NotBeforeUtc).ToUniversalTime() -gt [datetime]::UtcNow) {Add-TlsFinding 'High' 'Certificate is not yet valid' 'Observed' 'The certificate validity period has not started according to the scanner clock.' $Certificate 'Check system clocks and deploy a certificate valid for the current time.' ($BaseCommand+' -Checks Certificate')}
            if (-not $Certificate.SubjectAlternativeName) {Add-TlsFinding 'Low' 'Certificate subject alternative name absent' 'Review' 'Windows name validation can accept a matching Common Name, while some modern clients require a Subject Alternative Name. Client requirements determine the impact.' $Certificate 'Include appropriate DNS/IP Subject Alternative Names when issuing the certificate.' ($BaseCommand+' -Checks Certificate')}
            if ($Certificate.DaysRemaining -lt 0) {Add-TlsFinding 'High' 'Certificate expired' 'Observed' 'The server certificate has passed its expiry time.' $Certificate 'Renew and deploy a valid certificate.' ($BaseCommand+' -Checks Certificate')}
            elseif ($Certificate.DaysRemaining -lt 30) {Add-TlsFinding 'Medium' 'Certificate expires within 30 days' 'Review' 'The remaining certificate lifetime is short.' $Certificate 'Check renewal and deployment automation.' ($BaseCommand+' -Checks Certificate')}
            if ($Certificate.KeyAlgorithmOid -eq '1.2.840.113549.1.1.1' -and $Certificate.KeyBits -lt 2048) {Add-TlsFinding 'High' 'RSA certificate key below 2048 bits' 'Review' 'The observed certificate uses a small RSA key.' $Certificate 'Replace it with an appropriate modern key and certificate.' ($BaseCommand+' -Checks Certificate')}
            if ($Certificate.SignatureOid -in @('1.2.840.113549.1.1.4','1.2.840.113549.1.1.5','1.2.840.10045.4.1','1.2.840.10040.4.3')) {Add-TlsFinding 'High' 'Legacy certificate signature algorithm' 'Review' 'The leaf certificate uses MD5 or SHA-1.' $Certificate 'Replace the certificate with a modern signature algorithm.' ($BaseCommand+' -Checks Certificate')}
        }
        if (-not $Native.Success -or $Native.Error) {$Errors.Add([pscustomobject]@{Check='Native session / HTTP';Status='Inconclusive';Error=$Native.Error;Explanation='SslStream depends on local Schannel/.NET policy. A failed client handshake does not prove the server disables a protocol.'})}
        if ($Request -and $Native.HttpResponse) {
            $Http=Get-TlsHttpAnalysis $Native.HttpResponse $Native.HeaderLimitReached
            if ($Http.IsHttp -and -not $Http.Incomplete) {
                if (-not $Http.HstsEnabled) {Add-TlsFinding 'Medium' 'HSTS absent or disabled on tested response' 'Review' 'The tested HTTPS path did not return an active max-age policy. Relevance depends on whether this endpoint is intended for browsers.' $Http 'Review HSTS requirements for this hostname and response path.' ($BaseCommand+' -Checks Http')}
                $Csp=(@($Http.Headers | Where-Object Name -eq 'Content-Security-Policy').Value -join '; ')
                if (-not $Csp) {Add-TlsFinding 'Low' 'Content Security Policy absent on tested response' 'Review' 'No enforced CSP header was returned. Relevance depends on browser-served content; this does not establish an injection vulnerability.' $Http 'Define an appropriate CSP for browser applications; evaluate this path and response type.' ($BaseCommand+' -Checks Http')}
                $NoSniff=(@($Http.Headers | Where-Object Name -eq 'X-Content-Type-Options').Value -join ', ')
                if ($NoSniff.Trim() -ne 'nosniff') {Add-TlsFinding 'Low' 'Content type sniffing protection requires review' 'Review' 'The tested response did not return X-Content-Type-Options: nosniff. Browser content and accurate Content-Type headers determine relevance.' $Http 'Review nosniff and Content-Type settings for browser responses.' ($BaseCommand+' -Checks Http')}
                $Frames=(@($Http.Headers | Where-Object Name -eq 'X-Frame-Options').Value -join ', ')
                if ($Frames -notmatch '^(?i)(DENY|SAMEORIGIN)$' -and $Csp -notmatch '(?i)(?:^|;)\s*frame-ancestors\s+') {Add-TlsFinding 'Low' 'Framing protection absent on tested response' 'Review' 'No recognized X-Frame-Options or enforced CSP frame-ancestors directive was returned. This is a browser policy observation, not proof of clickjacking.' $Http 'Use an appropriate framing policy where browser pages need it.' ($BaseCommand+' -Checks Http')}
                foreach ($Cookie in $Http.Cookies) {if (-not $Cookie.Secure -or -not $Cookie.HttpOnly) {Add-TlsFinding 'Low' 'Cookie protection flags require review' 'Review' 'A returned Set-Cookie header lacks Secure or HttpOnly. Cookie purpose determines the appropriate flags.' $Cookie 'Protect sensitive cookies with appropriate flags and SameSite policy.' ($BaseCommand+' -Checks Http')}}
                if ($Http.ContentEncoding -match '(?i)gzip|deflate|br') {Add-TlsFinding 'Low' 'HTTP compression observed' 'Review' 'Compression is a BREACH prerequisite only when secrets and attacker-controlled input share a compressed response. HEAD does not establish body contents or exploitability.' $Http 'Assess responses containing secrets and reflected input; do not infer BREACH from compression alone.' ($BaseCommand+' -Checks Http')}
            } elseif ($Http.Incomplete) {$Errors.Add([pscustomobject]@{Check='HTTP';Status='Incomplete';Error='The complete response headers were not captured; no missing-header verdict is made.'})}
        } elseif ('Http' -in $SelectedChecks) {$Errors.Add([pscustomobject]@{Check='HTTP';Status='NotTested';Error=if($Upgrade -ne 'none'){'HTTP checks do not apply to the selected STARTTLS service.'}else{'No complete HTTP response was received.'}})}
    }
    $Extensions=@($ProtocolRows | Where-Object {$_.Selected -and $_.Version -ge 768} | ForEach-Object {[pscustomobject]@{Protocol=$_.Protocol;Compression=$_.Probe.Compression;Extensions=$_.Probe.Extensions;HelloRetryRequest=$_.Probe.HelloRetryRequest;SecureRenegotiationExtensionPresent=[bool](@($_.Probe.Extensions | Where-Object Id -eq 65281).Count)}})
    foreach ($Row in $Extensions) {if ($Row.Compression -gt 0) {Add-TlsFinding 'High' 'TLS-level compression selected' 'Review' 'TLS compression was selected; this is a CRIME prerequisite, not an exploit attempt.' $Row 'Disable TLS-level compression.' ($BaseCommand+' -Checks Extensions')}}
    $Counts=[ordered]@{};foreach($Severity in @('Critical','High','Medium','Low','Informational')){$Counts[$Severity]=@($script:TlsFindings | Where-Object Severity -eq $Severity).Count};$Counts.Total=$script:TlsFindings.Count
    $Report=[ordered]@{
        Metadata=[ordered]@{Tool='testssl.ps1';Version='1.0';ReferenceProject='https://github.com/testssl/testssl.sh';Implementation='Independent native PowerShell/.NET implementation; not affiliated with or equivalent to upstream testssl.sh';Target=$Endpoint;StartTls=$Upgrade;ChecksRequested=$SelectedChecks;StartedUtc=$Started.ToString('o');CompletedUtc=[datetime]::UtcNow.ToString('o');PowerShellVersion=[string]$PSVersionTable.PSVersion;ProbeTimeoutSeconds=$ProbeTimeout;ScanTimeoutSeconds=$ScanTimeout;DeadlineReached=($Watch.Elapsed.TotalSeconds -ge $ScanTimeout);RevocationRequested=$Revocation;AddressScope='One resolved/overridden IP address per invocation; other returned addresses are not scanned';HttpScope='One HEAD response, no redirects; captured headers can include cookie values';CipherCatalogCount=$Catalog.Count}
        SeveritySummary=$Counts;Findings=$script:TlsFindings.ToArray();Coverage=@(Get-TlsCoverage);Protocols=$ProtocolRows.ToArray();Ciphers=$CipherRows.ToArray();Preference=$Preferences.ToArray();Certificate=$Certificate;NativeSession=$Native;Extensions=$Extensions;Http=$Http;Errors=$Errors.ToArray()
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    $Destination=(Resolve-Path -LiteralPath $Destination).Path
    $SafeName=($Endpoint.Host -replace '[^A-Za-z0-9_.-]','_')+'_'+$Endpoint.Port+'_'+(Get-Date -Format 'yyyyMMdd_HHmmss_fff')
    $Files=@('json','txt','html','csv') | ForEach-Object {Join-Path $Destination ($SafeName+'.'+$_)}
    $Json=ConvertTo-Json -InputObject $Report -Depth 40 -WarningAction Stop
    $Json | Set-Content -LiteralPath $Files[0] -Encoding UTF8
    New-TlsReportText $Report $Json | Set-Content -LiteralPath $Files[1] -Encoding UTF8
    New-TlsReportHtml $Report | Set-Content -LiteralPath $Files[2] -Encoding UTF8
    if ($Report.Findings.Count) {$Report.Findings | Select-Object Severity,Finding,Status,Explanation,Command,Recommendation | Export-Csv -LiteralPath $Files[3] -NoTypeInformation -Encoding UTF8}
    else {'"Severity","Finding","Status","Explanation","Command","Recommendation"' | Set-Content -LiteralPath $Files[3] -Encoding UTF8}
    $Hashes=foreach($File in $Files){'{0}  {1}' -f (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash,[IO.Path]::GetFileName($File)}
    $Hashes | Set-Content -LiteralPath (Join-Path $Destination ($SafeName+'_SHA256.txt')) -Encoding UTF8
    Write-Host ('HTML: '+$Files[2]);Write-Host ('JSON: '+$Files[0]);Write-Host ('Findings: '+$Report.Findings.Count+'; incomplete/error observations: '+$Errors.Count)
    return [pscustomobject]@{Report=$Report;HtmlPath=$Files[2];JsonPath=$Files[0]}
}

$Endpoint=Resolve-TlsTarget $Target $Port $ServerName $ConnectAddress $TimeoutSeconds
Write-Host ('Scanning '+$Endpoint.Host+':'+$Endpoint.Port+' at '+$Endpoint.ConnectAddress+'; SNI/validation name: '+$Endpoint.ServerName)
$Result=Invoke-NativeTlsAudit $Endpoint $StartTls $Checks $TimeoutSeconds $ScanTimeoutSeconds ([bool]$CheckRevocation) $OutputDirectory $PSCommandPath
$Result | Select-Object HtmlPath,JsonPath
