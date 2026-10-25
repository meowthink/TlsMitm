# Every offline suite in one run. No admin and no WinDivert: the real MitmProxy is driven through
# FakeRedirector, so each mode is a loopback conversation the harness can judge itself.
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
# modes it covers.
$groups = @(
    ,@('smtp', 'smtpsplit', 'imap', 'pop3', 'ftp', 'nntp', 'xmpp', 'reject', 'ldap', 'ldap-decline', 'ldap-bad')
    ,@('ftps-pasv', 'ftps-epsv', 'ftps-active', 'ftps-active-split', 'ftps-active-clear')
    ,@('plain', 'implicit', 'implicit-ip', 'ipv6', 'early-data', 'https-close', 'alpn-fallback', 'alpn-h2')
    ,@('ech-relay', 'ech-downgrade', 'emsign', 'auto', 'handshake-abort', 'grease', 'rootcheck')
)

$failed = New-Object System.Collections.Generic.List[string]

# One solution build rather than one per project: every project references TlsMitm, so building them
# separately restores and evaluates the same graph again for each. chainprobe is in the solution and
# built here but not run below - it needs real endpoints - which is what catches API drift in it.
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
Write-Host "`n[run-offline] PASS - $modeCount starttlsprobe modes in $($groups.Count) processes + echcheck + no-sni-test"
