# Native PowerShell TLS scanner: review and coverage

Reviewed on 2026-10-09: [testssl.sh repository](https://github.com/testssl/testssl.sh), its [3.2 manual](https://github.com/testssl/testssl.sh/blob/3.2/doc/testssl.1.md), [source](https://github.com/testssl/testssl.sh/blob/3.2/testssl.sh), [README](https://github.com/testssl/testssl.sh/blob/3.2/Readme.md), and [license](https://github.com/testssl/testssl.sh/blob/3.2/LICENSE). The default repository branch is 3.3dev; the implementation comparison uses the stable 3.2 branch.

Upstream combines Bash socket probes with OpenSSL and data files. It covers protocol/cipher negotiation, certificates, service upgrades, HTTP configuration, client compatibility and specialized vulnerability probes. Its license is GPLv2. **testssl.ps1** is an independent implementation based on protocol specifications and .NET APIs; no upstream source, cipher database, client fingerprints or binaries are embedded. It is not an official port and does not claim equal coverage or upstream result equivalence.

The requested native Windows implementation uses one PowerShell file with an embedded C# helper compiled by the inbox Add-Type command. There is no runtime dependency on OpenSSL, WSL, Docker, Git Bash or project helper files. Windows PowerShell 5.1 and PowerShell 7 on Windows are supported. Constrained Language Mode or policies that prohibit Add-Type prevent execution.

## Coverage comparison

| Check family | Native implementation | Limit |
|---|---|---|
| SSLv2, SSLv3, TLS 1.0-1.3 | Explicit raw ClientHello and matching ServerHello selection | A selection is not a completed or authenticated session. Rejection is inconclusive; client offers and middleboxes can affect it |
| Individual cipher suites | 46 named suites, one offered at a time, on each observed TLS/SSLv3 protocol | Not the entire IANA registry or upstream cipher catalog; SSLv2 suites are not individually enumerated |
| Cipher categories | NULL, anonymous, EXPORT, RC4, DES/3DES, CBC, static RSA and authenticated AEAD examples | Findings describe configuration and attack prerequisites, not a confirmed named vulnerability |
| Server cipher preference | Two suites offered in both orders on TLS 1.2/1.3 | Pair-specific observation, not full ranking or proof of stability across a load balancer |
| Forward secrecy | Pre-TLS-1.3 suite key-exchange classification | Does not measure actual DH parameters or enumerate every curve/group. TLS 1.3 HRR does not establish a completed key exchange |
| Certificate | Windows chain/name validation, dates, SAN presence, key type/size, signature, SHA256 fingerprint, DER and captured chain | Windows trust/name policy may differ from browsers and upstream CA bundles. EV, alternate certificates and root-policy comparisons are not implemented |
| Revocation | Optional -CheckRevocation uses Windows policy | Separate OCSP stapling/must-staple evaluation is unsupported. Windows may fetch intermediate certificates even when revocation is off |
| HTTP | One HTTP/1.1 HEAD response: HSTS, CSP, nosniff, framing policy, cookie flags and compression observations; full selected headers | No redirect traversal, response-body analysis or browser execution. Missing policy headers are contextual Review findings; no claim of XSS/clickjacking/BREACH exploitability |
| STARTTLS | SMTP, IMAP, POP3, FTP, PostgreSQL | No authentication. Other service-upgrade protocols are unsupported |
| Extensions | ServerHello IDs and bytes; compression and renegotiation_info presence | No renegotiation attempt, full encrypted extension parsing or TLS group enumeration |
| Specialized probes | Explicit Unsupported coverage entries | Heartbleed, CCS injection, ROBOT, Ticketbleed, Winshock, DROWN, TLS_FALLBACK_SCSV, STARTTLS injection, resumption, ALPN/NPN, SCT, CAA, GREASE and browser/client simulation are not implemented |

Each generated report includes the same coverage disclosure, including unsupported checks. Failed connections, alerts, unknown results and deadlines never become a security pass.

## Run

```powershell
# HTTPS, all implemented check groups:
.\testssl.ps1 -Target 'https://server.example:443' -OutputDirectory 'C:\Temp\TLSReport'

# Select a particular backend while preserving SNI and certificate name:
.\testssl.ps1 -Target 'https://server.example:8443/path' -ConnectAddress '10.0.0.20' -ServerName 'server.example'

# SMTP STARTTLS; specify the service's actual port:
.\testssl.ps1 -Target 'mail.example:25' -StartTls smtp -Checks Protocols,Ciphers,Certificate,Extensions

# Smaller certificate and HTTP review:
.\testssl.ps1 -Target 'https://server.example/' -Checks Certificate,Http

# Optional Windows revocation checking:
.\testssl.ps1 -Target 'server.example:443' -Checks Certificate -CheckRevocation

# Bracket IPv6 addresses:
.\testssl.ps1 -Target '[2001:db8::10]:443' -ServerName 'server.example'
```

- Every invocation targets one endpoint/IP. All resolved addresses are recorded, but only the chosen IPv4-first address is scanned. Use -ConnectAddress to repeat the scan for other backends.
- Default probe deadline is 5 seconds; the default scan budget is 600 seconds. -TimeoutSeconds and -ScanTimeoutSeconds adjust them. Budget checks happen between probes. DNS has its own lookup wait; Windows certificate/provider work can outlive an asynchronous handshake wait.
- -Checks accepts Protocols, Ciphers, Certificate, Http, Extensions and Preference. Cipher/extension/preference checks first collect protocol selection. Preference needs Ciphers in the selected groups and at least two selected suites. HTTP is skipped for STARTTLS services.
- Use the appropriate DNS name for SNI and certificate validation. Port 443 is assumed unless a port is supplied. -Port overrides a URL/target port. URL credentials and fragments are rejected.
- The scanner makes multiple TCP/TLS connections, closes raw probes after selection, and sends a HEAD request when HTTP checking is selected. It does not change the target configuration or perform exploit, memory-disclosure or denial-of-service attempts.

## Evidence and interpretation

JSON and TXT retain selected structured evidence, raw request/response record hex, service-upgrade transcripts, certificate DER/chain, captured HTTP headers, coverage and errors. TXT follows the layout in **reference/testssl_output.txt**: banner, endpoint/start details, protocols, cipher categories/preferences, forward secrecy, server/certificate defaults, HTTP headers, vulnerability indicators, client simulations, rating and completion footer. It uses actual scan values and labels missing/inconclusive/unsupported results explicitly; it never copies the template's target, results, OpenSSL engine description or grade. Aligned text summaries are followed by a full selected-evidence JSON appendix, so commands, nested records and long captured responses are preserved. The template is a development reference, not a runtime dependency.

HTML has collapsible sections, sortable severity-first findings, a filter, explanations, repeatable commands and saved evidence. CSV summarizes findings; it does not contain the full evidence. SHA256 manifests cover the four output artifacts.

Raw TLS responses are bounded to 128 KiB, 32 records and 18,432 bytes per TLS record. HTTP response headers are bounded to 64 KiB. STARTTLS lines/transcripts are bounded. Reaching a bound or losing a connection produces incomplete/inconclusive evidence, preserves captured bytes/headers, and prevents missing-header verdicts. Evidence is limited to the messages selected by these probes; it is not a full packet capture or an authenticated transcript for a raw hello probe.

TLS 1.3 raw probes send an empty key-share vector and stop at a validated HelloRetryRequest. They check the selected protocol/cipher, legacy version, session ID echo and requested group. **ServerHelloObserved** and **HelloRetryRequestObserved** mean selection was observed. **NativeSession.Success** means a separate Windows SslStream connection completed its handshake; check **CertificateValid** and **PolicyErrors** separately. A handshake may complete while the audit callback records an untrusted certificate, allowing evidence collection only on that connection. No process-wide validation policy or trust store is changed.

Cipher findings are configuration observations. A selected CBC suite does not establish LUCKY13, SSLv2 does not complete a DROWN assessment, and HTTP compression does not establish BREACH. Unknown/unsupported results are gaps requiring other checks. Missing browser headers may be irrelevant to an API or non-browser endpoint. Cookie values, URL queries and server banners are included in collected evidence.

Repeatable commands rerun a check group and write fresh timestamped reports. They preserve endpoint, SNI, IP and URL path. The report never executes command strings received from a server or saved in evidence. A successful test is not a compliance certification or guarantee that every protocol/client/attack was tested.

## Design references and validation

Wire framing and ServerHello interpretation follow [TLS 1.2, RFC 5246](https://www.rfc-editor.org/rfc/rfc5246.html) and [TLS 1.3, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html). The empty TLS 1.3 key-share vector is described in RFC 8446 section 4.2.8. All 46 cipher IDs/names were checked against the [IANA TLS cipher registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml). Completed sessions use [SslStream](https://learn.microsoft.com/en-us/dotnet/api/system.net.security.sslstream), with a per-connection validation callback. Upgrades follow [SMTP RFC 3207](https://www.rfc-editor.org/rfc/rfc3207.html), [IMAP/POP3 RFC 2595](https://www.rfc-editor.org/rfc/rfc2595.html), [FTP RFC 4217](https://www.rfc-editor.org/rfc/rfc4217.html), and the [PostgreSQL protocol documentation](https://www.postgresql.org/docs/current/protocol-flow.html).

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-Tls.ps1
pwsh -NoProfile -File .\tests\Test-Tls.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-TlsText.ps1
pwsh -NoProfile -File .\tests\Test-TlsText.ps1
```

Tests use isolated loopback C# servers and disposable self-signed certificates without installing a trust anchor. They cover real Windows TLS 1.2 handshakes and TLS 1.3 selection when available, all five STARTTLS adapters, untrusted certificates, URL/IPv6 parsing, fragment reassembly, malformed/duplicate extensions, unoffered suites, record bounds, timeouts, partial captures, HTTP policies, HTML escaping, standalone CLI output and hashes. They do not scan a remote production service or replace validation on your deployed endpoints.
