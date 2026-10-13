<#
 =============================================================================
  Kargo Network Test  -  Windows (PowerShell 5.1 or later)
  Version 2.1  (2026-10-09)

  Run this from a laptop that is ON THE SAME NETWORK AND VLAN the Kargo
  devices will use, physically at the dock doors where the towers will be
  installed.

  Usage (from PowerShell, no admin rights needed):
      powershell -ExecutionPolicy Bypass -File .\kargo-network-test-WINDOWS.ps1

  Output: console summary + kargo-network-test-results.txt
          Email the results file back to your Kargo contact.

  This script only makes OUTBOUND connections. It changes nothing on the
  machine or the network, and installs nothing.

  Changes in 2.1 (from 2.0)
    - FIXES A FALSE FAILURE. 2.0 offered TLS 1.2 only. t01.tunnel.kargo.zone
      serves an ECDSA certificate at TLS 1.2, so a laptop whose cipher policy
      restricts ECDHE-ECDSA had no way to complete the handshake and the
      report blamed the firewall. 1.2 and 1.3 are both offered now.
    - Certificates are VALIDATED, not just read: chain and hostname are checked,
      and the issuer check is kept on top. Both are needed - on a managed
      laptop the corporate inspection CA is usually trusted, so an intercepted
      connection validates fine and only the issuer name gives it away.
    - A TLS-layer failure is no longer reported as a blocked port. The two are
      distinguished and named separately.
    - Each TLS check prints the protocol, cipher and certificate key type it
      actually negotiated, so a report can be compared against another site's
      without re-testing.
    - DNS, TCP and UDP checks are retried. A single dropped packet used to be
      reported as a blocked port. The link-health section deliberately does not
      retry, because it is measuring loss.
    - UDP 3478 is checked with a Tailscale-format STUN request (SOFTWARE
      "tailnode" plus FINGERPRINT); the server drops anything else silently.
      "No reply" and "a reply that was not valid STUN" are now reported
      separately - the second means UDP egress works and is not a firewall
      problem.
 =============================================================================
#>

$ErrorActionPreference = 'SilentlyContinue'
# Offer TLS 1.2 AND 1.3. Pinning 1.2 alone removed the client's only escape route:
# t01.tunnel.kargo.zone serves an ECDSA cert at TLS 1.2 and an RSA cert at TLS 1.3,
# so a Windows build whose policy restricts ECDHE-ECDSA suites could not complete a
# 1.2 handshake and, pinned, never reached 1.3. macOS/Linux (curl) always negotiated
# 1.3 and never saw it. Tls13 is only a defined enum member on .NET Framework 4.8+,
# so it is added only where it exists.
$protos = [Net.SecurityProtocolType]::Tls12
if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
    $protos = $protos -bor [Net.SecurityProtocolType]::Tls13
}
[Net.ServicePointManager]::SecurityProtocol = $protos

$Results = Join-Path (Get-Location) 'kargo-network-test-results.txt'
try { '' | Set-Content -Path $Results -ErrorAction Stop }
catch {
    $Results = Join-Path $env:TEMP 'kargo-network-test-results.txt'
    '' | Set-Content -Path $Results
    Write-Host "Current folder is not writable - writing results to $Results instead" -ForegroundColor Yellow
}
$script:Pass = 0; $script:Fail = 0; $script:Warn = 0

function Say([string]$t) { Write-Host $t; Add-Content -Path $Results -Value $t }
function Hdr([string]$t) { Write-Host ""; Write-Host $t -ForegroundColor Cyan; Add-Content -Path $Results -Value "`r`n$t" }

function Res([string]$Status, [string]$Label, [string]$Detail) {
    switch ($Status) {
        'PASS'   { $script:Pass++;   $c = 'Green'  }
        'FAIL'   { $script:Fail++;   $c = 'Red'    }
        'WARN'   { $script:Warn++;   $c = 'Yellow' }
    }
    Write-Host ("  [{0,-6}] " -f $Status) -ForegroundColor $c -NoNewline
    Write-Host ("{0,-46} {1}" -f $Label, $Detail)
    Add-Content -Path $Results -Value ("  [ {0,-6} ] {1,-46} {2}" -f $Status, $Label, $Detail)
}

# Retried. A single dropped SYN reported as a blocked port is the most expensive
# wrong answer this script can give - it sends a network team after a rule that
# was never the problem.
function Test-Tcp([string]$H, [int]$P) {
    for ($n = 0; $n -lt 2; $n++) {
        if (Test-TcpOnce $H $P) { return $true }
    }
    return $false
}

# The link-health section must NOT retry: it is counting how many of ten attempts
# succeed, and a retry would hide exactly the packet loss it exists to measure.
function Test-TcpOnce([string]$H, [int]$P) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect($H, $P, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(6000, $false)) { $c.Close(); return $false }
        $c.EndConnect($iar); $c.Close(); return $true
    } catch { return $false }
}

function Get-CertInfo([string]$H, [int]$P, [string]$Sni) {
    # Returns an object with Issuer/Subject on success, or with Err describing why.
    # Distinguishing "TCP would not open" from "TCP opened but TLS failed" matters:
    # reporting a TLS failure as "port blocked or dropped" contradicts the TCP
    # section of this same report and sends network teams hunting a firewall rule
    # that is not the problem.
    $out = New-Object psobject -Property @{ Issuer = $null; Subject = $null; Err = $null; TcpOk = $false; Neg = $null; Verified = $false; PolicyErr = $null }
    $c = $null
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect($H, $P, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(8000, $false)) {
            $c.Close(); $out.Err = 'TCP connect timed out - port blocked or dropped'; return $out
        }
        $c.EndConnect($iar)
        $out.TcpOk = $true
    } catch {
        if ($c) { $c.Close() }
        $out.Err = 'TCP connect failed - port blocked or dropped (' + $_.Exception.Message + ')'
        return $out
    }

    # Build the protocol set: TLS 1.2 + 1.3 where available, then 1.2 alone as a
    # fallback for older .NET / Schannel that cannot do 1.3.
    $T = [System.Security.Authentication.SslProtocols]
    $attempts = @()
    if ([Enum]::GetNames($T) -contains 'Tls13') { $attempts += ($T::Tls12 -bor $T::Tls13) }
    $attempts += $T::Tls12

    $lastErr = $null
    foreach ($proto in $attempts) {
        try {
            # Record what validation actually concluded, then accept the
            # certificate anyway so it can still be read and reported. Rejecting
            # here would throw, and we would lose the issuer line that identifies
            # the interceptor - the single most useful line in the report.
            #
            # Validation and the issuer check catch different faults and both are
            # needed. On a managed laptop the corporate inspection CA is normally
            # installed, so an intercepted connection validates perfectly and only
            # the issuer name gives it away; on a laptop without that CA the chain
            # fails instead, which the issuer check alone would not explain.
            $script:PolicyErr = 'Unknown'
            $cb = [System.Net.Security.RemoteCertificateValidationCallback] {
                param($s,$cert,$chain,$err)
                $script:PolicyErr = [string]$err
                return $true
            }
            $ss = New-Object System.Net.Security.SslStream($c.GetStream(), $false, $cb)
            # The single-argument AuthenticateAsClient overload ignores
            # ServicePointManager.SecurityProtocol and negotiates TLS 1.0 on
            # PowerShell 5.1, so the protocol set is always passed explicitly.
            $ss.AuthenticateAsClient($Sni, $null, $proto, $false)
            $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ss.RemoteCertificate)
            $out.Issuer = $x.Issuer; $out.Subject = $x.Subject
            # Record WHAT was negotiated, not just that something was. A host can
            # serve a different certificate per protocol version - t01 serves ECDSA
            # at TLS 1.2 and RSA at TLS 1.3 - so a client that lacks ECDHE-ECDSA
            # suites fails at 1.2 and succeeds at 1.3 on the same open port. Without
            # these three values in the report that is invisible and reads as a
            # network fault.
            $ka = 'unknown-key'
            try {
                switch ($x.GetKeyAlgorithm()) {
                    '1.2.840.113549.1.1.1' { $ka = 'RSA' }
                    '1.2.840.10045.2.1'    { $ka = 'ECDSA' }
                    default                { $ka = $x.GetKeyAlgorithm() }
                }
            } catch {}
            $cs = $null
            # NegotiatedCipherSuite exists only on .NET Core 3+ / PowerShell 7 - on
            # Windows PowerShell 5.1 reading it throws, so it is probed, not assumed.
            try { if ($ss.PSObject.Properties['NegotiatedCipherSuite']) { $cs = [string]$ss.NegotiatedCipherSuite } } catch {}
            if (-not $cs) {
                try {
                    $cs = [string]$ss.CipherAlgorithm
                    $hv = [string]$ss.HashAlgorithm
                    # AEAD suites report HashAlgorithm as None - printing "Aes256/None"
                    # reads like a missing value rather than a normal GCM result.
                    if ($hv -and $hv -ne 'None') { $cs = $cs + '/' + $hv }
                } catch { $cs = 'n/a' }
            }
            $out.Neg = [string]$ss.SslProtocol + ', ' + $cs + ', ' + $ka + ' cert'
            $out.PolicyErr = $script:PolicyErr
            $out.Verified = ($script:PolicyErr -eq 'None')
            $ss.Close(); $c.Close()
            return $out
        } catch {
            $lastErr = $_.Exception.Message
            # The stream is unusable after a failed handshake - reopen for the retry.
            try { $c.Close() } catch {}
            if ($proto -ne $attempts[-1]) {
                try {
                    $c = New-Object System.Net.Sockets.TcpClient
                    $iar = $c.BeginConnect($H, $P, $null, $null)
                    if (-not $iar.AsyncWaitHandle.WaitOne(8000, $false)) { break }
                    $c.EndConnect($iar)
                } catch { break }
            }
        }
    }
    # Name only what was actually tried. If every attempt failed on an open port the
    # cause is local - a restricted cipher policy or an old Schannel - not a firewall.
    $tried = @()
    foreach ($a in $attempts) { $tried += [string]$a }
    $out.Err = 'TCP connected but the TLS handshake failed (tried ' + ($tried -join '; ') + ') - ' + $lastErr
    return $out
}

function Get-Crc32([byte[]]$Bytes) {
    # No CRC32 in PowerShell, and PowerShell parses 0xFFFFFFFF as Int32 -1,
    # so this is done in Int64 and masked back to 32 bits.
    if (-not $script:CrcTable) {
        $script:CrcTable = New-Object 'int64[]' 256
        for ($i = 0; $i -lt 256; $i++) {
            $c = [int64]$i
            for ($k = 0; $k -lt 8; $k++) {
                if ($c -band 1) { $c = (3988292384 -bxor ($c -shr 1)) -band 4294967295 }
                else            { $c = ($c -shr 1) -band 4294967295 }
            }
            $script:CrcTable[$i] = $c
        }
    }
    $crc = [int64]4294967295
    foreach ($b in $Bytes) {
        $crc = ($script:CrcTable[[int](($crc -bxor $b) -band 255)] -bxor ($crc -shr 8)) -band 4294967295
    }
    return ($crc -bxor 4294967295) -band 4294967295
}

# Returns @{ Ok; Ip; Port; State }
#   State: 'ok'      valid STUN binding response
#          'silent'  nothing came back after 3 attempts - the port is blocked
#          'invalid' something came back but it was not a valid STUN response,
#                    which means UDP egress works and something is answering on
#                    3478. Reporting that as "blocked" would send a firewall team
#                    after a rule that is already correct.
function Get-StunMappedAddress([string]$H, [int]$P) {
    $out = New-Object psobject -Property @{ Ok = $false; Ip = ''; Port = 0; State = 'silent' }
    $txid = New-Object byte[] 12
    for ($i = 0; $i -lt 12; $i++) { $txid[$i] = [byte](Get-Random -Minimum 0 -Maximum 256) }

    # 32-byte prefix: header + SOFTWARE. The fingerprint CRC covers exactly this.
    $pre = New-Object byte[] 32
    $pre[0]=0x00; $pre[1]=0x01; $pre[2]=0x00; $pre[3]=0x14      # body len = 20
    $pre[4]=0x21; $pre[5]=0x12; $pre[6]=0xA4; $pre[7]=0x42
    [Array]::Copy($txid, 0, $pre, 8, 12)
    $pre[20]=0x80; $pre[21]=0x22; $pre[22]=0x00; $pre[23]=0x08  # SOFTWARE, len 8
    $sw = [Text.Encoding]::ASCII.GetBytes('tailnode')
    [Array]::Copy($sw, 0, $pre, 24, 8)

    $fp = ((Get-Crc32 $pre) -bxor 1398035790) -band 4294967295   # 0x5354554E
    $pkt = New-Object byte[] 40
    [Array]::Copy($pre, $pkt, 32)
    $pkt[32]=0x80; $pkt[33]=0x28; $pkt[34]=0x00; $pkt[35]=0x04  # FINGERPRINT last
    $pkt[36]=[byte](($fp -shr 24) -band 255); $pkt[37]=[byte](($fp -shr 16) -band 255)
    $pkt[38]=[byte](($fp -shr 8)  -band 255); $pkt[39]=[byte]($fp -band 255)

    # Retried: UDP is lossy, and one dropped datagram reported as "port blocked"
    # is exactly the false FAIL this test exists to avoid.
    $r = $null
    for ($attempt = 0; $attempt -lt 3 -and -not $r; $attempt++) {
        try {
            $u = New-Object System.Net.Sockets.UdpClient
            $u.Client.ReceiveTimeout = 5000
            # Connect() so the kernel drops datagrams from any other source.
            $u.Connect($H, $P)
            [void]$u.Send($pkt, 40)
            $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $r = $u.Receive([ref]$ep)
            $u.Close()
        } catch {
            $r = $null
            try { $u.Close() } catch {}
        }
    }
    if (-not $r) { $out.State = 'silent'; return $out }

    # Something answered, so the datagram left the building. From here every
    # failure is "not a valid STUN response", never "blocked".
    $out.State = 'invalid'
    if ($r.Length -lt 20) { return $out }
    if ($r[0] -ne 0x01 -or $r[1] -ne 0x01) { return $out }
    if ($r[4] -ne 0x21 -or $r[5] -ne 0x12 -or $r[6] -ne 0xA4 -or $r[7] -ne 0x42) { return $out }
    # The transaction ID is enforced, not merely noted: without this check any
    # stray datagram carrying the magic cookie would count as a pass.
    for ($i = 0; $i -lt 12; $i++) { if ($r[8 + $i] -ne $txid[$i]) { return $out } }
    $out.Ok = $true
    $out.State = 'ok'

    # Mask for XOR-MAPPED-ADDRESS: magic cookie, then the transaction ID.
    # IPv4 uses the first 4 bytes; IPv6 uses all 16.
    $mask = New-Object byte[] 16
    $mask[0]=0x21; $mask[1]=0x12; $mask[2]=0xA4; $mask[3]=0x42
    [Array]::Copy($txid, 0, $mask, 4, 12)

    $i = 20
    while (($i + 4) -le $r.Length) {
        # [int] casts matter: -shl keeps the left operand's type, so a [byte]
        # shifted left by 8 would evaluate to 0.
        $t  = ([int]$r[$i]   -shl 8) -bor $r[$i+1]
        $ln = ([int]$r[$i+2] -shl 8) -bor $r[$i+3]
        $v  = $i + 4
        if (($t -eq 0x0020 -or $t -eq 0x8020) -and ($v + 4) -le $r.Length) {
            $fam = $r[$v + 1]
            # The port is XORed with the top half of the magic cookie.
            $out.Port = ((([int]$r[$v + 2] -shl 8) -bor $r[$v + 3]) -bxor 0x2112) -band 0xFFFF
            $n = 0
            if ($fam -eq 1) { $n = 4 } elseif ($fam -eq 2) { $n = 16 }
            if ($n -gt 0 -and ($v + 4 + $n) -le $r.Length) {
                $raw = New-Object byte[] $n
                for ($k = 0; $k -lt $n; $k++) { $raw[$k] = [byte]($r[$v + 4 + $k] -bxor $mask[$k]) }
                if ($n -eq 16) {
                    # ::ffff:a.b.c.d - flatten to the IPv4 address
                    $mapped = $true
                    for ($k = 0; $k -lt 10; $k++) { if ($raw[$k] -ne 0) { $mapped = $false } }
                    if ($mapped -and $raw[10] -eq 255 -and $raw[11] -eq 255) {
                        $raw = $raw[12..15]
                    }
                }
                $out.Ip = (New-Object System.Net.IPAddress(,$raw)).ToString()
                return $out
            }
        } elseif ($t -eq 0x0001 -and ($v + 8) -le $r.Length) {
            $out.Ip = (New-Object System.Net.IPAddress(,$r[($v+4)..($v+7)])).ToString()
            return $out
        }
        $i += 4 + $ln
        if ($ln % 4 -ne 0) { $i += 4 - ($ln % 4) }
    }
    return $out
}

# ---------------------------------------------------------------------------
Say "==============================================================="
Say " KARGO NETWORK TEST v2.1"
Say (" Run at : " + (Get-Date))
Say (" Host   : " + $env:COMPUTERNAME)
Say (" OS     : " + (Get-CimInstance Win32_OperatingSystem).Caption)
Say "==============================================================="
Say ""
Say "Site / customer name : ______________________________________"
Say "Dock door(s) tested  : ______________________________________"
Say "SSID or switch port  : ______________________________________"
Say "VLAN ID              : ______________________________________"
Say "Tested by            : ______________________________________"
Say ""

# ---------- 0. Environment --------------------------------------------------
Hdr "0. TEST ENVIRONMENT"

if (-not (Get-Command Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {
    Res 'WARN' 'Local IP address / gateway / DNS' 'could not check on this OS - run "ipconfig /all" and record the values'
} else {
    $cfg = Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
    if ($cfg) {
        Res 'PASS' 'Local IP address obtained (DHCP/static)' $cfg.IPv4Address.IPAddress
        Say ("  Interface        : " + $cfg.InterfaceAlias)
        Say ("  Default gateway  : " + $cfg.IPv4DefaultGateway.NextHop)
        Say ("  Site DNS servers : " + ($cfg.DNSServer.ServerAddresses -join ' '))
    } else {
        Res 'FAIL' 'Local IP address obtained (DHCP/static)' 'no interface with a default gateway - check DHCP / cabling / Wi-Fi'
    }
}

# One probe, two jobs. sdn.kargo.zone runs a Tailscale-format STUN server on UDP
# 3478, so a single tailnode-format binding request both proves that port is open
# (section 6) and reports the public address the server saw us from - which is how
# we know the technician is really on the site's network. The address comes from a
# host already on the Kargo whitelist, so no extra rule and no third-party service.
$stun = Get-StunMappedAddress 'sdn.kargo.zone' 3478
if ($stun.Ok -and $stun.Ip) {
    $src = ''
    if ($stun.Port -gt 0) { $src = ', source port ' + $stun.Port }
    Say ("  Public egress IP : " + $stun.Ip + "   (as seen by sdn.kargo.zone" + $src + ")")
    Say "      ^ Confirm with your IT team that this is THIS SITE's public IP. If it"
    Say "        is not, a VPN, proxy or exit node is in the path and every result"
    Say "        below describes the wrong network."
} else {
    Say "  Public egress IP : could not determine (see the UDP 3478 result below)"
}

# Local VPN detection. This is the check that actually gates the run, because it does
# not depend on any external service being reachable.
$vpnWhy = @()
if (Get-Command Get-NetAdapter -ErrorAction SilentlyContinue) {
    $vpn = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and ($_.InterfaceDescription -match 'VPN|TAP|Tailscale|WireGuard|AnyConnect|GlobalProtect|ZScaler|Netskope') }
    if ($vpn) { $vpnWhy += (($vpn.Name -join ', ') + ' is UP') }
} else {
    Res 'WARN' 'VPN / SASE client check' 'could not check on this OS - confirm no VPN, Zscaler or Netskope client is running'
}
# Tailscale leaves fingerprints even when the adapter check misses it.
if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
    $rs = (Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ServerAddresses) -join ' '
    if ($rs -match '100\.100\.100\.100') { $vpnWhy += "Tailscale MagicDNS (100.100.100.100) is this machine's resolver" }
}
$cgnat = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
         Where-Object { $_.IPAddress -match '^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.' }
if ($cgnat) { $vpnWhy += 'this machine holds a Tailscale/CGNAT 100.64.0.0/10 address' }
if (Get-Command tailscale -ErrorAction SilentlyContinue) {
    tailscale status *> $null
    if ($LASTEXITCODE -eq 0) { $vpnWhy += 'the tailscale CLI reports an active tailnet' }
}

if ($vpnWhy.Count -gt 0) {
    Res 'FAIL' 'No VPN active on test machine' (($vpnWhy -join '; ') + ' - disconnect it and re-run, these results are not valid')
} else {
    Res 'PASS' 'No VPN detected on test machine' 'note: proxy-based clients (Zscaler, Netskope) leave no adapter - check the egress IP above'
}

# ---------- 1. Captive portal ----------------------------------------------
Hdr "1. CAPTIVE PORTAL CHECK  (Kargo devices cannot use captive-portal networks)"
try {
    $r = Invoke-WebRequest -Uri 'http://connectivitycheck.gstatic.com/generate_204' -UseBasicParsing -TimeoutSec 10 -MaximumRedirection 0
    if ($r.StatusCode -eq 204) { Res 'PASS' 'No captive portal on this network' 'HTTP 204 as expected' }
    else { Res 'FAIL' 'No captive portal on this network' ("got HTTP " + $r.StatusCode + " instead of 204 - portal / interception present") }
} catch {
    Res 'WARN' 'Captive portal check' 'no clean response - plain HTTP egress may be blocked or a portal is redirecting'
}

# ---------- 2. DNS ----------------------------------------------------------
Hdr "2. DNS RESOLUTION   what matters is correct answers, not which resolver"
if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
    Res 'WARN' 'Configured resolver returns correct addresses' 'could not check on this OS - run "nslookup sdn.kargo.zone" and "nslookup t01.tunnel.kargo.zone"'
} else {
    # PRIMARY: whatever resolver this machine is configured with must return correct answers.
    $siteDnsOk = $true
    $expected = @{ 'sdn.kargo.zone' = '13.56.25.183'; 't01.tunnel.kargo.zone' = '54.153.23.224' }
    foreach ($name in $expected.Keys) {
        $a = (Resolve-DnsName -Name $name -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
        if (-not $a) {
            Res 'FAIL' ("Configured resolver resolves " + $name) 'no answer - DNS is not working on this network'
            $siteDnsOk = $false
        } elseif ($a -eq $expected[$name]) {
            Res 'PASS' ("Configured resolver resolves " + $name) $a
        } else {
            Res 'FAIL' ("Configured resolver resolves " + $name) ("got $a, expected " + $expected[$name] + " - resolver is returning a modified answer")
            $siteDnsOk = $false
        }
    }
    $d = (Resolve-DnsName -Name 'edp12.devicecloud.com' -Type A -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
    if ($d) { Res 'PASS' 'Configured resolver resolves edp12.devicecloud.com' $d }
    else    { Res 'FAIL' 'Configured resolver resolves edp12.devicecloud.com' 'site resolver cannot resolve this name'; $siteDnsOk = $false }

    # SECONDARY: 8.8.8.8 is only required as a fallback when the site resolver is unusable.
    $g = (Resolve-DnsName -Name 'sdn.kargo.zone' -Server 8.8.8.8 -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
    if ($g -eq '13.56.25.183') {
        Res 'PASS' '8.8.8.8 reachable (optional fallback)' $g
    } elseif ($g) {
        # An answer came back, but the wrong one - outbound DNS is being intercepted
        # and rewritten. This is a real fault, never "acceptable".
        Res 'FAIL' '8.8.8.8 returns a modified answer' ("got $g, expected 13.56.25.183 - external DNS is being intercepted and rewritten")
    } elseif ($siteDnsOk) {
        Res 'WARN' '8.8.8.8 reachable (optional fallback)' 'blocked - acceptable, because the configured resolver is answering correctly'
    } else {
        Res 'FAIL' '8.8.8.8 reachable (required here)' 'the configured resolver is not answering correctly AND 8.8.8.8 is blocked - one of the two must work'
    }
}

# ---------- 3. TCP ----------------------------------------------------------
Hdr "3. TCP ENDPOINTS"
$tcp = @(
    @{ L = 't01 tunnel  (TCP 443)';                H = 't01.tunnel.kargo.zone'; P = 443  },
    @{ L = '54.153.23.224 SSH tunnel (TCP 8022)';  H = '54.153.23.224';         P = 8022 },
    @{ L = 'Digi Remote Manager (TCP 3199)';       H = 'edp12.devicecloud.com'; P = 3199 },
    @{ L = 'sdn.kargo.zone (TCP 443)';             H = 'sdn.kargo.zone';        P = 443  },
    @{ L = 'sdn.kargo.zone (TCP 80)';              H = 'sdn.kargo.zone';        P = 80   }
)
foreach ($t in $tcp) {
    if (Test-Tcp $t.H $t.P) { Res 'PASS' $t.L ($t.H + ':' + $t.P + ' open') }
    else { Res 'FAIL' $t.L ($t.H + ':' + $t.P + ' unreachable - firewall / whitelist') }
}

# ---------- 4. HTTPS --------------------------------------------------------
Hdr "4. APPLICATION-LEVEL HTTPS"
try {
    $b = (Invoke-WebRequest -Uri 'https://t01.tunnel.kargo.zone/robots.txt' -UseBasicParsing -TimeoutSec 12).Content
    if ($b -match 'Disallow') { Res 'PASS' 'https://t01.tunnel.kargo.zone/robots.txt' 'returned expected robots.txt body' }
    else { Res 'FAIL' 'https://t01.tunnel.kargo.zone/robots.txt' 'unexpected body returned' }
} catch {
    # Retry once on TLS 1.2 alone, in case this box advertises Tls13 in the enum
    # but Schannel will not actually negotiate it.
    $firstErr = $_.Exception.Message
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $b = (Invoke-WebRequest -Uri 'https://t01.tunnel.kargo.zone/robots.txt' -UseBasicParsing -TimeoutSec 12).Content
        if ($b -match 'Disallow') { Res 'PASS' 'https://t01.tunnel.kargo.zone/robots.txt' 'returned expected robots.txt body (TLS 1.2)' }
        else { Res 'FAIL' 'https://t01.tunnel.kargo.zone/robots.txt' 'unexpected body returned' }
    } catch {
        Res 'FAIL' 'https://t01.tunnel.kargo.zone/robots.txt' $firstErr
    }
    [Net.ServicePointManager]::SecurityProtocol = $protos
}

try {
    $r2 = Invoke-WebRequest -Uri 'https://sdn.kargo.zone/' -UseBasicParsing -TimeoutSec 12
    Res 'PASS' 'https://sdn.kargo.zone/ responds' ("HTTP " + $r2.StatusCode + " (any status = TLS reached the server)")
} catch {
    if ($_.Exception.Response) { Res 'PASS' 'https://sdn.kargo.zone/ responds' ("HTTP " + [int]$_.Exception.Response.StatusCode + " (any status = TLS reached the server)") }
    else { Res 'FAIL' 'https://sdn.kargo.zone/ responds' 'no HTTPS response' }
}

# ---------- 5. TLS inspection ----------------------------------------------
Hdr "5. TLS / HTTPS INSPECTION   (must be DISABLED for these hosts)"
foreach ($h in @('t01.tunnel.kargo.zone','sdn.kargo.zone')) {
    $ci = Get-CertInfo $h 443 $h
    if (-not $ci.Issuer) { Res 'FAIL' ($h + ' cert issuer') $ci.Err; continue }
    # The detail line goes AFTER its own result row. Printed before, it sits directly
    # under the PREVIOUS test's verdict and reads as if it belongs to that one - which
    # has already caused a certificate from one host to be read as another host's.
    if ($ci.Issuer -match "Let's Encrypt") {
        if ($ci.Verified) {
            Res 'PASS' ($h + ' cert issuer') 'issuer OK, chain and hostname verified - no interception'
        } else {
            # The issuer name is right but the certificate does not validate. That
            # is either an inspection product copying the name, or a genuine
            # certificate fault. This check cannot tell which, so it does not say.
            Res 'FAIL' ($h + ' cert issuer') 'issuer name looks correct but the certificate did NOT validate - see detail below'
        }
    } else {
        Res 'FAIL' ($h + ' cert issuer') 'UNEXPECTED ISSUER - TLS inspection is intercepting this host'
    }
    Say ("           ^ " + $h + " issuer=" + $ci.Issuer)
    if ($ci.Neg) { Say ("           ^ " + $h + " negotiated=" + $ci.Neg) }
    if ($ci.Verified) { Say ("           ^ " + $h + " certificate chain and hostname validated against the Windows trust store") }
    else { Say ("           ^ " + $h + " certificate did NOT validate - " + $ci.PolicyErr) }
}
$dg = Get-CertInfo 'edp12.devicecloud.com' 3199 'edp12.devicecloud.com'
if (-not $dg.Issuer) { Res 'FAIL' 'Digi EDP TLS handshake (port 3199)' $dg.Err }
else {
    if ($dg.Issuer -match 'Digi|devicecloud' -or $dg.Subject -match 'Digi|devicecloud') { Res 'PASS' 'Digi EDP TLS handshake (port 3199)' 'genuine Digi certificate presented' }
    else { Res 'FAIL' 'Digi EDP TLS handshake (port 3199)' 'NON-DIGI certificate - inspection on port 3199' }
    Say ("           ^ edp12.devicecloud.com issuer=" + $dg.Issuer)
    if ($dg.Neg) { Say ("           ^ edp12.devicecloud.com negotiated=" + $dg.Neg) }
    # Digi issue this from their own CA, which is in no public trust store, so a
    # chain failure here is expected and is not evidence of interception.
    Say "           ^ edp12.devicecloud.com uses a private Digi CA - identity is judged from the subject, not the chain"
}

# ---------- 6. UDP -----------------------------------------------------------
Hdr "6. UDP ENDPOINTS"

# UDP 3478 IS conclusively testable, but only with a Tailscale-format request: the
# server requires SOFTWARE="tailnode" plus a valid FINGERPRINT and drops anything
# else silently, so a generic STUN client wrongly reports the port as blocked.
if ($stun.Ok) {
    $d = 'valid STUN response'
    if ($stun.Ip) { $d = $d + ', egress IP ' + $stun.Ip }
    Res 'PASS' 'sdn.kargo.zone UDP 3478' $d
} elseif ($stun.State -eq 'invalid') {
    Res 'WARN' 'sdn.kargo.zone UDP 3478' 'a reply came back but it was not a valid STUN response - UDP egress works, something unexpected is answering on 3478'
} else {
    Res 'FAIL' 'sdn.kargo.zone UDP 3478' 'no reply after 3 attempts - UDP 3478 blocked'
}

# ---------- 7. Link health --------------------------------------------------
Hdr "7. LINK HEALTH"
$times = @()
for ($i = 0; $i -lt 10; $i++) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    if (Test-TcpOnce 'sdn.kargo.zone' 443) { $sw.Stop(); $times += $sw.ElapsedMilliseconds } else { $sw.Stop() }
}
if ($times.Count -gt 0) {
    $avg = [math]::Round(($times | Measure-Object -Average).Average, 0)
    $mx  = ($times | Measure-Object -Maximum).Maximum
    $loss = (10 - $times.Count) * 10
    Say ("  TCP connect samples: " + $times.Count + "/10   avg " + $avg + "ms   worst " + $mx + "ms   failed " + $loss + "%")
    if ($times.Count -lt 10) { Res 'FAIL' 'Connection stability to sdn.kargo.zone' ("$loss% of connections failed - packet loss or flapping") }
    elseif ($avg -gt 250)    { Res 'WARN' 'Latency to sdn.kargo.zone' ("${avg}ms avg - above the 250ms comfort threshold") }
    else                     { Res 'PASS' 'Latency & stability to sdn.kargo.zone' ("${avg}ms avg, 10/10 connections") }
} else {
    Res 'FAIL' 'Latency & stability to sdn.kargo.zone' 'no successful connections'
}

$wifi = netsh wlan show interfaces 2>$null | Select-String 'Signal|SSID|Radio type'
if ($wifi) { Say "  Wi-Fi:"; $wifi | ForEach-Object { Say ("    " + $_.ToString().Trim()) } }

# ---------- Summary ---------------------------------------------------------
Hdr "SUMMARY"
Say ("  PASS: $script:Pass    FAIL: $script:Fail    WARN: $script:Warn")
Say ""
if ($script:Fail -eq 0 -and $script:Warn -eq 0) {
    Say "  Everything this script can verify passed."
} elseif ($script:Fail -eq 0) {
    Say "  No failures. Review the WARN lines above - they are usually acceptable."
} else {
    Say ("  " + $script:Fail + " check(s) FAILED. Send the results file to your Kargo contact and to")
    Say "  your network/firewall team - each failing line names the exact host, port"
    Say "  and protocol that needs to be allowed."
}

Hdr "STILL TO DO - NOT CHECKED BY THIS SCRIPT"
Say "  These three requirements cannot be proven from a laptop. They are on the"
Say "  results sheet in the Kargo Network Test PDF and still need completing:"
Say ""
Say "    1. UDP 41641 to 13.56.25.183, 3.151.242.46"
Say "       and 54.176.130.49                           firewall rule review"
Say "    2. Upload bandwidth, 20 Mbps per active dock   measure at the dock"
Say "    3. Wi-Fi at least -67 dBm at each tower"
Say "       position, or LTE 1-2 bars                   measure at the dock"
Say ""
Write-Host ("Results written to " + $Results) -ForegroundColor White

