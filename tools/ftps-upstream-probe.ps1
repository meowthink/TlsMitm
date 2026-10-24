# Does the .NET TLS client stack, i.e. exactly what MitmProxy uses for its upstream leg, get a
# login reply from a real FTPS server? Prints response codes only; the password never leaves the
# netrc parser. Run with the proxy stopped so the connection is genuinely direct.
param(
    [string]$Host_ = 'sft.rohde-schwarz.com',
    [int]$Port = 990
)

function Read-Netrc([string]$machine) {
    foreach ($f in @("$env:USERPROFILE\.netrc", "$env:USERPROFILE\_netrc")) {
        if (-not (Test-Path $f)) { continue }
        $tok = (Get-Content $f -Raw) -split '\s+'
        for ($i = 0; $i -lt $tok.Count - 4; $i++) {
            if ($tok[$i] -eq 'machine' -and $tok[$i + 1] -eq $machine -and
                $tok[$i + 2] -eq 'login' -and $tok[$i + 4] -eq 'password') {
                return @($tok[$i + 3], $tok[$i + 5])
            }
        }
    }
    return $null
}

$cred = Read-Netrc $Host_
if (-not $cred) { Write-Host "NO NETRC ENTRY for $Host_"; exit 3 }
Write-Host "netrc entry found: login=$($cred[0]) passwordLen=$($cred[1].Length)"

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($Host_, $Port)
$net = $client.GetStream()

$ssl = New-Object System.Net.Security.SslStream($net, $false, { param($s, $c, $ch, $e) $script:policyErr = $e; $true })
$props = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13

function Read-Reply($reader) {
    $sb = New-Object System.Text.StringBuilder
    while ($true) {
        $line = $reader.ReadLine()
        if ($null -eq $line) { return "<connection closed with no reply>" }
        [void]$sb.AppendLine($line)
        # A reply is finished when the 4th char is a space, not a hyphen.
        if ($line.Length -ge 4 -and $line[3] -eq ' ') { break }
    }
    $sb.ToString().Trim()
}

try {
    $ssl.AuthenticateAsClient($Host_, $null, $props, $false)
    Write-Host "UPSTREAM TLS OK  version=$($ssl.SslProtocol)  cipher=$($ssl.NegotiatedCipherSuite)  policy=$script:policyErr"

    $w = New-Object System.IO.StreamWriter($ssl)
    $w.NewLine = "`r`n"; $w.AutoFlush = $true
    $r = New-Object System.IO.StreamReader($ssl)

    Write-Host "greeting : $(Read-Reply $r)"
    $w.Write("USER $($cred[0])`r`n"); Write-Host "USER->   : $(Read-Reply $r)"
    $w.Write("PASS `$hidden`r`n".Replace('$hidden', $cred[1])); Write-Host "PASS->   : $(Read-Reply $r)"
    $w.Write("PBSZ 0`r`n");            Write-Host "PBSZ->   : $(Read-Reply $r)"
    $w.Write("PROT P`r`n");            Write-Host "PROT->   : $(Read-Reply $r)"
    $w.Write("SYST`r`n");              Write-Host "SYST->   : $(Read-Reply $r)"
    $w.Write("QUIT`r`n")
}
catch {
    Write-Host "FAILED: $($_.Exception.GetType().Name): $($_.Exception.Message)"
    if ($_.Exception.InnerException) { Write-Host "  inner: $($_.Exception.InnerException.Message)" }
}
finally {
    $ssl.Dispose(); $client.Close()
}
