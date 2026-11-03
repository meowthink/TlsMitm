# Every offline suite in one run. No admin and no WinDivert handle: the real MitmProxy is driven through
# FakeRedirector, so each mode is a loopback conversation the harness can judge itself. One suite does load
# WinDivert.dll to call its userspace checksum helper, which needs no handle, no driver and no admin.
# Stop a live TlsMitm first - it intercepts this suite's loopback traffic and makes the FTPS and
# emSign modes fail for reasons that have nothing to do with the code under test.
param([string]$Configuration = 'Debug')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (Get-Process TlsMitm -ErrorAction SilentlyContinue) {
    throw 'TlsMitm is running. Stop it before running the offline suite.'
}

# starttlsprobe runs any number of modes in one process, and what a mode costs before its
# conversation even starts does not depend on the mode: root-store read, CRL build, cert engine
# (~0.6s measured). Grouped by protocol family, so a group that hangs or crashes still names the
# modes it covers. The media group's last mode hands its session to a third-party client and skips
# itself when TLSMITM_FFMPEG is unset, so the group stays green on a machine with no ffmpeg.
$groups = @(
    ,@('smtp', 'smtpsplit', 'imap', 'pop3', 'ftp', 'nntp', 'xmpp', 'xmpp-split', 'xmpp-nosni', 'xmpp-decline', 'xmpp-bad', 'reject', 'ldap', 'ldap-decline', 'ldap-bad', 'sunrpc', 'sunrpc-split', 'sunrpc-unavail', 'sunrpc-decline', 'sunrpc-misuse', 'sunrpc-near', 'sunrpc-bad', 'sunrpc-wrong-token', 'sunrpc-wrong-flavor')
    ,@('ftps-pasv', 'ftps-epsv', 'ftps-active', 'ftps-active-split', 'ftps-active-clear')
    ,@('plain', 'implicit', 'implicit-ip', 'ipv6', 'early-data', 'https-close', 'alpn-fallback', 'alpn-h2', 'mtls-refused')
    ,@('rtsps', 'rtmps', 'sips', 'rtmps-ffmpeg')
    ,@('ech-relay', 'ech-downgrade', 'emsign', 'auto', 'handshake-abort', 'grease', 'rootcheck', 'filter', 'early-refuse')
)

$failed = New-Object System.Collections.Generic.List[string]

# One solution build rather than one per project: every project references TlsMitm, so building them
# separately restores and evaluates the same graph again for each. chainprobe and tools/abortcheck are
# in the solution and built here but not run below - they need real endpoints - which is what catches
# API drift in them.
$t0 = [DateTime]::UtcNow
dotnet build (Join-Path $root 'TlsMitm.slnx') -c $Configuration --nologo | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'build failed' }
Write-Host ("[run-offline] build {0:N1}s" -f ([DateTime]::UtcNow - $t0).TotalSeconds)

$probe = Join-Path $root "tests\starttlsprobe\bin\$Configuration\net10.0\starttlsprobe.exe"
foreach ($g in $groups) {
    $out = & $probe $g 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { $failed.Add("starttlsprobe $($g -join ' ')"); Write-Host $out }
    else { Write-Host "ok   starttlsprobe $($g -join ' ')" }
}

# echcheck is the only suite left that is its own executable: it drives no sockets at all, just the
# ECH state machine with an injected clock.
$ech = Join-Path $root "tests\echcheck\bin\$Configuration\net10.0\echcheck.exe"
$out = & $ech 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('echcheck'); Write-Host $out } else { Write-Host 'ok   echcheck' }

# natcheck judges the router's NAT rewrite on synthetic packets: no driver, no admin, no sockets.
$nat = Join-Path $root "tests\natcheck\bin\$Configuration\net10.0\natcheck.exe"
$out = & $nat 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('natcheck'); Write-Host $out } else { Write-Host 'ok   natcheck' }

# flowcheck judges the redirector's flow table on synthetic keys: which connections share a state, what
# token each one gets, what ageing frees. It is the only check that can name the two-LAN-clients-on-one-
# port case, since a live run needs a second machine to produce it.
$flow = Join-Path $root "tests\flowcheck\bin\$Configuration\net10.0\flowcheck.exe"
$out = & $flow 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('flowcheck'); Write-Host $out } else { Write-Host 'ok   flowcheck' }

# fwcheck pins what the inbound reachability probe is made of: the SYN's own header octets, the address
# it claims to come from, a token no live flow holds, and which rule port fields name the relay port.
# It never opens the firewall COM object, so it says nothing about this machine's policy.
$fwc = Join-Path $root "tests\fwcheck\bin\$Configuration\net10.0\fwcheck.exe"
$out = & $fwc 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('fwcheck'); Write-Host $out } else { Write-Host 'ok   fwcheck' }

# servcheck drives the router's DHCP pool and resolver the same way: client messages in, reply bytes
# asserted, and an injected transport standing in for the upstream.
$svc = Join-Path $root "tests\servcheck\bin\$Configuration\net10.0\servcheck.exe"
$out = & $svc 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('servcheck'); Write-Host $out } else { Write-Host 'ok   servcheck' }

# v6check is the same shape for the IPv6 side: the DHCPv6 prefix-delegation client (datagrams in,
# datagrams and prefix lifetimes out) and the Router Advertisement the LAN is given (bytes out). Both
# take their clock and their jitter as parameters, so no timer and no socket is involved.
$v6 = Join-Path $root "tests\v6check\bin\$Configuration\net10.0\v6check.exe"
$out = & $v6 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('v6check'); Write-Host $out } else { Write-Host 'ok   v6check' }

# nat64check is RFC 6146's stateful table on the same terms: datagrams in, the outgoing 5-tuple and the
# BIB/STE state out. Its clock is injected, so the two-hour, four-minute and sixty-second lifetimes and the
# fragment window are all aged without waiting, and no port, socket or driver is touched.
$n64 = Join-Path $root "tests\nat64check\bin\$Configuration\net10.0\nat64check.exe"
$out = & $n64 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('nat64check'); Write-Host $out } else { Write-Host 'ok   nat64check' }

# quiccheck pins the QUIC long-header layout the blocker drops on. The version sits immediately after
# the flags byte; reading it from anywhere else makes every real datagram miss and HTTP/3 walk past.
$quic = Join-Path $root "tests\quiccheck\bin\$Configuration\net10.0\quiccheck.exe"
$out = & $quic 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { $failed.Add('quiccheck'); Write-Host $out } else { Write-Host 'ok   quiccheck' }

$noSni = Join-Path $PSScriptRoot 'no-sni-test.ps1'
if (-not (Get-Command pwsh -ErrorAction SilentlyContinue)) {
    throw 'no-sni-test needs PowerShell 7 (pwsh); Windows PowerShell cannot load a net10.0 assembly'
}
& pwsh -NoProfile -ExecutionPolicy Bypass -File $noSni -Configuration $Configuration
if ($LASTEXITCODE -ne 0) { $failed.Add('no-sni-test') } else { Write-Host 'ok   no-sni-test' }

if ($failed.Count -gt 0) {
    Write-Host "`n[run-offline] FAIL ($($failed.Count))"
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}
$modeCount = ($groups | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
Write-Host "`n[run-offline] PASS - $modeCount starttlsprobe modes in $($groups.Count) processes + echcheck + natcheck + nat64check + flowcheck + fwcheck + servcheck + v6check + quiccheck + no-sni-test"
