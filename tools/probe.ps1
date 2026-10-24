param(
    [string]$Ip = '39.96.0.227',
    [string]$Host_ = 'gateway.qoder.com.cn',
    [string]$Alpn = 'http/1.1',
    [int]$Port = 443
)

$ErrorActionPreference = 'Stop'

$verdict = [hashtable]@{ errors = 'n/a'; chainOk = 'n/a'; leaf = 'n/a'; issuer = 'n/a'; chainStatus = @() }

$callback = [System.Net.Security.RemoteCertificateValidationCallback] {
    param($sender, $certificate, $chain, $sslPolicyErrors)
    $script:verdict.errors = "$sslPolicyErrors"
    $script:verdict.chainOk = "$($chain.ChainStatus)"
    if ($certificate) {
        $script:verdict.leaf = $certificate.Subject
        $script:verdict.issuer = $certificate.Issuer
    }
    if ($chain) {
        $script:verdict.chainStatus = @($chain.ChainElements | ForEach-Object {
            "$($_.Certificate.Subject)  [status=$($_.Certificate.ChainElementStatus.StatusInformation -join ';')]"
        })
    }
    return $true
}

$tcp = [System.Net.Sockets.TcpClient]::new()
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$tcp.Connect($Ip, $Port)
Write-Output "TCP connected to $Ip`:$Port in $($sw.ElapsedMilliseconds)ms  local=$($tcp.Client.LocalEndPoint) remote=$($tcp.Client.RemoteEndPoint)"

$net = $tcp.GetStream()
$ssl = [System.Net.Security.SslStream]::new($net, $false, $callback)

$opts = [System.Net.Security.SslClientAuthenticationOptions]::new()
$opts.TargetHost = $Host_
$opts.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
$opts.CertificateRevocationCheckMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$ap = [System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]]::new()
$ap.Add([System.Net.Security.SslApplicationProtocol]::new($Alpn))
$opts.ApplicationProtocols = $ap

try {
    $ssl.AuthenticateAsClient($opts)
    Write-Output "HANDSHAKE OK proto=$($ssl.SslProtocol) cipher=$($ssl.CipherAlgorithm) negotiatedAlpn='$($ssl.NegotiatedApplicationProtocol)'"
} catch {
    Write-Output "HANDSHAKE FAILED: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    Write-Output "  inner: $($_.Exception.InnerException)"
}

Write-Output "POLICY_ERRORS = $($verdict.errors)"
Write-Output "LEAF_SUBJECT  = $($verdict.leaf)"
Write-Output "LEAF_ISSUER   = $($verdict.issuer)"
foreach ($c in $verdict.chainStatus) { Write-Output "  CHAIN: $c" }

if ($ssl.IsAuthenticated) {
    $req = "GET / HTTP/1.1`r`nHost: $Host_`r`nUser-Agent: tlsmitm-probe/1.0`r`nAccept: */*`r`nConnection: close`r`n`r`n"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
    $ssl.Write($bytes, 0, $bytes.Length)
    $ssl.Flush()
    Write-Output "SENT $($bytes.Length) bytes of HTTP request"

    $buf = New-Object byte[] 16384
    $total = 0
    $reads = 0
    $ssl.ReadTimeout = 15000
    try {
        while ($true) {
            $n = $ssl.Read($buf, 0, $buf.Length)
            if ($n -le 0) { break }
            $total += $n
            $reads++
            if ($reads -eq 1) {
                $preview = [System.Text.Encoding]::UTF8.GetString($buf, 0, [Math]::Min(200, $n)) -replace '\r?\n', ' | '
                Write-Output "FIRST RESPONSE ($n bytes): $preview"
            }
            if ($total -gt 200000) { break }
        }
    } catch {
        Write-Output "READ FAILED after $total bytes : $($_.Exception.Message)"
    }
    Write-Output "RECV $total bytes in $reads reads  elapsed=$($sw.ElapsedMilliseconds)ms"
}

$ssl.Dispose()
$tcp.Close()
