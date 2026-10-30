# Exercises the shipped ClientHello parser and the leaf-SAN choice without admin, without WinDivert
# and without network. The parser is reached by reflection over the built assembly; each hello is
# replayed through a loopback socket pair because the caller passes the already-peeked first byte.
param([string]$Configuration = 'Debug')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$root = Split-Path -Parent $PSScriptRoot
$dll = Join-Path $root "TlsMitm\bin\$Configuration\net10.0\TlsMitm.dll"
if (-not (Test-Path $dll)) { throw "Build first: dotnet build `"$root\TlsMitm\TlsMitm.csproj`" -c $Configuration" }

# Windows PowerShell 5.1 runs on .NET Framework and cannot reflect over a net10.0 assembly.
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this with pwsh (PowerShell 7)' }

function Log([string]$Text) { Write-Host $Text }

$asm = [System.Reflection.Assembly]::LoadFrom($dll)
$proxyType = $asm.GetType('TlsMitm.MitmProxy')
$readHello = $proxyType.GetMethod('ReadClientHelloAsync', [System.Reflection.BindingFlags]::Static -bor [System.Reflection.BindingFlags]::NonPublic)
if (-not $readHello) { throw 'ReadClientHelloAsync not found' }

function Add-BE16 {
    param($List, [int]$Value)
    $List.Add([byte](($Value -shr 8) -band 0xFF))
    $List.Add([byte]($Value -band 0xFF))
}

function New-ClientHello {
    param([string]$Sni, [byte[]]$Extra)
    $exts = New-Object System.Collections.Generic.List[byte]
    if ($Sni) {
        $name = [System.Text.Encoding]::ASCII.GetBytes($Sni)
        Add-BE16 $exts 0x0000
        Add-BE16 $exts (2 + 1 + 2 + $name.Length)
        Add-BE16 $exts (3 + $name.Length)
        $exts.Add([byte]0x00)
        Add-BE16 $exts $name.Length
        $exts.AddRange([byte[]]$name)
    }
    if ($Extra) { $exts.AddRange($Extra) }

    $body = New-Object System.Collections.Generic.List[byte]
    $body.AddRange([byte[]](0x03, 0x03))                           # client_version
    $body.AddRange([byte[]](1..32 | ForEach-Object { [byte]($_ % 251) })) # random
    $body.Add([byte]0x00)                                          # session_id length
    $body.AddRange([byte[]](0x00, 0x02, 0x00, 0x2F))               # 1 cipher suite
    $body.AddRange([byte[]](0x01, 0x00))                           # 1 compression method
    Add-BE16 $body $exts.Count
    $body.AddRange($exts)

    $hs = New-Object System.Collections.Generic.List[byte]
    $hs.Add([byte]0x01)                                            # handshake_type = ClientHello
    $bl = $body.Count
    $hs.Add([byte](($bl -shr 16) -band 0xFF))
    $hs.Add([byte](($bl -shr 8) -band 0xFF))
    $hs.Add([byte]($bl -band 0xFF))
    $hs.AddRange($body)

    $rec = New-Object System.Collections.Generic.List[byte]
    $rec.AddRange([byte[]](0x16, 0x03, 0x01))
    Add-BE16 $rec $hs.Count
    $rec.AddRange($hs)
    , $rec.ToArray()
}

function Invoke-Parser {
    param([byte[]]$Hello)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = $listener.LocalEndpoint.Port
        $peer = [System.Net.Sockets.TcpClient]::new('127.0.0.1', $port)
        $accepted = $listener.AcceptTcpClient()
        try {
            $ns = $accepted.GetStream()
            $peer.GetStream().Write($Hello, 0, $Hello.Length)
            $peer.GetStream().Flush()

            # HandleClientAsync peeks the record type first, then passes it in as firstByte -
            # the stream must be positioned after that byte.
            $one = New-Object byte[] 1
            $peek = $ns.ReadAsync($one, 0, 1)
            $peek.Wait(1000) | Out-Null
            $firstByte = $one[0]

            $cts = [System.Threading.CancellationTokenSource]::new(3000)
            $task = $readHello.Invoke($null, [object[]]@($ns, [byte]$firstByte, $cts.Token))
            try {
                if (-not $task.Wait(3000)) { return [pscustomobject]@{ Parsed = $false; Sni = '<TIMEOUT>'; RawLen = 0 } }
                $vt = $task.GetType().GetProperty('Result').GetValue($task)
                $info = $vt.Item1
                if ($null -eq $info) { return [pscustomobject]@{ Parsed = $false; Sni = $null; RawLen = $vt.Item2.Length } }
                $sni = $info.GetType().GetProperty('ServerName').GetValue($info)
                [pscustomobject]@{ Parsed = $true; Sni = $sni; RawLen = $vt.Item2.Length }
            } catch {
                $inner = $_.Exception
                while ($inner.InnerException) { $inner = $inner.InnerException }
                Log ("  EX: {0}: {1}" -f $inner.GetType().Name, $inner.Message)
                return [pscustomobject]@{ Parsed = $false; Sni = '<EXCEPTION>'; RawLen = 0 }
            }
        } finally { $accepted.Close(); $peer.Close() }
    } finally { $listener.Stop() }
}

# status_request (0x000a), length 0 - exercises the per-extension offset advance
$statusRequest = [byte[]](0x00, 0x0A, 0x00, 0x00)
$renegotiationInfo = [byte[]](0xFF, 0x01, 0x00, 0x01, 0x00)

$h1 = New-ClientHello -Sni 'probe.test' -Extra $statusRequest
$h2 = New-ClientHello -Extra $statusRequest
$h3 = New-ClientHello
$h4 = New-ClientHello -Sni 'a.test' -Extra ($statusRequest + $renegotiationInfo)

$cases = @(
    @{ Label = 'sni-present';   Hello = $h1; WantSni = 'probe.test' }
    @{ Label = 'no-sni';        Hello = $h2; WantSni = $null }
    @{ Label = 'no-extensions'; Hello = $h3; WantSni = $null }
    @{ Label = 'sni-then-exts'; Hello = $h4; WantSni = 'a.test' }
)

$failures = 0
foreach ($c in $cases) {
    $r = Invoke-Parser -Hello $c.Hello
    $ok = $r.Parsed -and ($r.Sni -eq $c.WantSni)
    if (-not $ok) { $failures++ }
    Log ("{0} {1,-14} parsed={2,-5} sni='{3}' rawBytes={4}" -f `
        $(if ($ok) { 'ok  ' } else { 'FAIL' }), $c.Label, $r.Parsed, $r.Sni, $r.RawLen)
}

# Leaf SAN type for an address-literal name, signed by a throwaway in-memory CA (real stores untouched)
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$caReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=TEST_THROWAWAY_CA', $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
$caReq.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true, $false, 0, $true))
$caCert = $caReq.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-3), [DateTimeOffset]::UtcNow.AddYears(5))
$caWithKey = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $caCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, ''), '',
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

$certEngineType = $asm.GetType('TlsMitm.CertEngine')
$modeType = $asm.GetType('TlsMitm.CertEngineMode')
$fiddlerOnly = [System.Enum]::Parse($modeType, 'FiddlerOnly')
$ctor = $certEngineType.GetConstructors()[0]
$engine = $ctor.Invoke([object[]]@($caWithKey, $null, $fiddlerOnly, $null))
foreach ($name in @('203.0.113.10', 'probe.test')) {
    $leaf = $engine.GetCert($name).Leaf
    $san = $leaf.Extensions | Where-Object { $_.Oid.FriendlyName -like '*Alternative*' }
    $text = $san.Format($false)
    $want = if ($name -match '^\d+\.\d+\.\d+\.\d+$') { 'IP Address=' } else { 'DNS Name=' }
    $ok = $text -like "*$want*"
    if (-not $ok) { $failures++ }
    Log ("{0} leaf '{1}' SAN: {2}" -f $(if ($ok) { 'ok  ' } else { 'FAIL' }), $name, $text)

    # Chromium refuses a leaf whose own span exceeds the CA/Browser Forum ceiling (SC-081v3: 200 days
    # since 2026-03-15) with ERR_CERT_VALIDITY_TOO_LONG, no matter how long the issuer lives.
    $span = ($leaf.NotAfter - $leaf.NotBefore).TotalDays
    $vok = ($span -le 200) -and ($leaf.NotBefore -le [datetime]::Now) -and ($leaf.NotAfter -ge [datetime]::Now.AddDays(7))
    if (-not $vok) { $failures++ }
    Log ("{0} leaf '{1}' validity: {2:N1} days ({3:yyyy-MM-dd} .. {4:yyyy-MM-dd})" -f `
        $(if ($vok) { 'ok  ' } else { 'FAIL' }), $name, $span, $leaf.NotBefore, $leaf.NotAfter)
}
$rsa.Dispose()

Log $(if ($failures -eq 0) { '[no-sni-test] PASS' } else { "[no-sni-test] FAIL ($failures)" })
exit $(if ($failures -eq 0) { 0 } else { 1 })
