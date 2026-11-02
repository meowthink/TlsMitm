# Does a run take its firewall rule back when the console ends without a chance to clean up?
#
# Both programs release the rule they added on any end they can see: Ctrl+C, their own 3 s watchdog, and the
# console close through TlsMitm/ConsoleClose.cs. `taskkill /F` is the one terminator that reaches nothing, so
# the second run here is the control: it is expected to strand the rule, and only that contrast makes the
# first run's clean store mean anything.
#
# Run elevated, from a shell that will not swallow the child's output:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\closecheck.ps1 -Program router
# Read the VERDICT lines at the end. The criterion is the store's count, never the log's last line.
param(
    [ValidateSet('router','tlsmitm')][string]$Program = 'router',
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Exe,
    [string]$LanAddress,
    [string]$WanAddress,
    [int]$WaitForRules = 60,
    [string]$OutFile = (Join-Path $env:TEMP 'closecheck.out'),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
$shapes = @{
    router  = @{ exe = "$RepoRoot\Router\bin\Debug\net10.0\Router.exe"
                 rules = 'router-lan-in', 'router-dns-tcp-in'
                 extra = '--allow-lan-in', '--stats', '10' }
    tlsmitm = @{ exe = "$RepoRoot\TlsMitm\bin\Debug\net10.0\TlsMitm.exe"
                 rules = 'tlsmitm-relay-in'
                 extra = '--allow-relay-in' }
}
$shape = $shapes[$Program]
$script:names = $shape.rules
$script:routerExe = if ($Exe) { $Exe } else { $shape.exe }
$script:routerDir = Split-Path -Parent $script:routerExe
$script:runArgs = $null
# Every process this script started, so the end of a run can say whether it reaped them all. The host keeps
# its own shells open, so "is anything still running" is asked about these pids and these two names only.
$script:spawned = @()
$out = $OutFile

function Say([string]$m) { Write-Host $m; Add-Content -LiteralPath $out -Value $m }
function Count([string]$n) { (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Measure-Object).Count }
function Counts { ($names | ForEach-Object { "$_=$(Count $_)" }) -join ' ' }
function Alive([System.Diagnostics.Process]$p) { (Get-Process -Id $p.Id -ErrorAction SilentlyContinue) -ne $null }
# tlsmitm holds one rule and router two, so the store check has to walk whatever this program's shape names.
function Released([string]$reading) {
    foreach ($n in $names) { if ($reading -notmatch "$([regex]::Escape($n))=0") { return $false } }
    return $true
}

function Invoke-Run([string]$tag, [string]$killVerb) {
    $logPath = Join-Path $env:TEMP "closecheck-$tag.log"
    if (Test-Path $logPath) { Remove-Item $logPath -Force }
    $arguments = if ($script:runArgs) { $script:runArgs } else { @('--lan', $lanIp) + $shape.extra }
    $p = Start-Process -FilePath $script:routerExe -ArgumentList $arguments `
         -WorkingDirectory $script:routerDir -PassThru -WindowStyle Hidden -RedirectStandardOutput $logPath
    $script:spawned += $p.Id
    Say "[$tag] pid=$($p.Id) started; waiting up to $WaitForRules s for the rules to appear"
    # -1 = the process died on its own, -2 = the rules never appeared. Only 0..N means "there is a live run
    # holding the rules", which is the only state a terminator can be judged in: Router takes the rules back
    # and returns 1 when its own inbound probe finds them filtered, so a store that reads empty at kill time
    # can mean either "the close released them" or "nothing ever held them".
    $seen = -2
    for ($i = 0; $i -lt $WaitForRules; $i++) {
        if ((Count $names[0]) -ge 1) { $seen = $i; break }
        if (-not (Alive $p)) { $seen = -1; break }
        Start-Sleep -Seconds 1
    }
    if ($seen -eq -1) {
        Say "[$tag] the process was already gone at $(Get-Date -Format 'HH:mm:ss') - no kill was sent, so this run proves nothing. Read $logPath."
        Get-Content $logPath -ErrorAction SilentlyContinue | Select-Object -Last 12 | ForEach-Object { Say "[$tag]   $($_)" }
        return $logPath
    }
    if ($seen -lt 0) {
        Say "[$tag] the rules never appeared within ${WaitForRules}s while the process stayed alive; killing it to leave nothing running."
        & taskkill /F /PID $p.Id 2>&1 | ForEach-Object { Say "[$tag] taskkill: $_" }
        $p.WaitForExit(15000) | Out-Null
        Get-Content $logPath -ErrorAction SilentlyContinue | Select-Object -Last 12 | ForEach-Object { Say "[$tag]   $($_)" }
        return $logPath
    }
    Say "[$tag] after ${seen}s: alive=$(Alive $p)  $(Counts)"
    Say "[$tag] taskkill $killVerb at $(Get-Date -Format 'HH:mm:ss.fff')"
    if ($killVerb -eq 'close') { & taskkill /PID $p.Id 2>&1 | ForEach-Object { Say "[$tag] taskkill: $_" } }
    else { & taskkill /F /PID $p.Id 2>&1 | ForEach-Object { Say "[$tag] taskkill: $_" } }
    $dead = $p.WaitForExit(15000)
    Start-Sleep -Seconds 2
    Say "[$tag] exited=$dead at $(Get-Date -Format 'HH:mm:ss.fff')  $(Counts)"
    Say "[$tag] log's own verdict lines:"
    Get-Content $logPath -ErrorAction SilentlyContinue |
        Select-String "Added '|already in the store|inbound probe|removed again|did not put|not added|Firewall:" |
        ForEach-Object { Say "[$tag]   $($_.Line)" }
    return $logPath
}

if (Test-Path $out) { Remove-Item $out -Force }
Say "=== closecheck started $(Get-Date -Format 'HH:mm:ss') program=$Program elevated=$((([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) ==="

if ($SelfTest) {
    # The two ways a run can be unwitnessed, exercised without a firewall write: an executable that stays
    # alive and never claims a rule, and one that exits before the wait can see anything.
    $Script:lanIp = '192.168.99.1'
    Say '--- case A: an alive process that adds no rule -> must take the "never appeared" branch and leave nothing running'
    $script:routerExe = (Get-Command powershell.exe).Source
    $script:routerDir = Split-Path -Parent $script:routerExe
    $script:runArgs = @('-NoProfile', '-Command', 'Start-Sleep 120')
    $WaitForRules = 10
    Invoke-Run 'stub' 'close' | Out-Null
    Say "  store now: $(Counts)"
    Say '--- case B: the real program, unelevated and with a LAN address no interface holds -> "already gone" branch'
    $script:routerExe = $shape.exe
    $script:routerDir = Split-Path -Parent $shape.exe
    $script:runArgs = $null
    Invoke-Run 'gone' 'close' | Out-Null
    Say "  store now: $(Counts)"
    Say '--- processes left behind (expect none):'
    foreach ($id in $script:spawned) {
        $still = Get-Process -Id $id -ErrorAction SilentlyContinue
        if ($still) { Say "  leftover pid=$id $($still.ProcessName)" }
    }
    Get-CimInstance Win32_Process -Filter 'Name="Router.exe" OR Name="TlsMitm.exe"' |
        ForEach-Object { Say "  a $($_.Name) is running that this script did not start: pid=$($_.ProcessId)" }
    return
}

if (-not (Test-Path $script:routerExe)) { Say "ABORT: $script:routerExe not found (build $Program first)"; return }
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Say 'ABORT: this writes firewall rules, so it has to run elevated. Nothing was started and no rule was touched.'
    Say "  powershell -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Program $Program"
    return
}

Say "--- before: $(Counts)"
Say "--- SharedAccess=$((Get-Service SharedAccess -ErrorAction SilentlyContinue).Status) icssvc=$((Get-Service icssvc -ErrorAction SilentlyContinue).Status)"

$startedAp = $false
if (-not $LanAddress) {
    # An AP, because both programs refuse a LAN address on an interface that is not connected. No client joins
    # on purpose: nobody gets a lease, and the listeners still bind.
    Say '--- starting the hosted network'
    $upBefore = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.ifIndex })
    Say((netsh wlan start hostednetwork | Out-String).Trim())
    Start-Sleep -Seconds 5
    $upNow = Get-NetAdapter -ErrorAction SilentlyContinue |
             Where-Object { $_.Status -eq 'Up' -and $_.Name -like 'Local Area Connection*' }
    # Prefer the interface that was not Up a moment ago: that is the one this start made, and a Wi-Fi Direct
    # group owner's adapter would otherwise be indistinguishable from the hosted network's by name alone.
    $sap = $upNow | Where-Object { $upBefore -notcontains $_.ifIndex } | Select-Object -First 1
    if ($null -eq $sap) { $sap = $upNow | Select-Object -First 1 }
    if ($null -eq $sap) {
        Say 'ABORT: no hosted-network interface came Up, so nothing was started beyond the radio. No rule was touched.'
        Say((netsh wlan show hostednetwork | Select-String 'Status|Number of clients' | Out-String).Trim())
        return
    }
    $startedAp = $true
    $LanAddress = (Get-NetIPAddress -InterfaceIndex $sap.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                   Where-Object { $_.IPAddress -notlike '169.254*' } | Select-Object -First 1).IPAddress
    Say "--- LAN: ifIdx=$($sap.ifIndex) $($sap.Name) addr=$LanAddress"
}
$Script:lanIp = $LanAddress
if (-not $WanAddress) {
    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
             Sort-Object RouteMetric | Select-Object -First 1
    $WanAddress = (Get-NetIPAddress -InterfaceIndex $route.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.IPAddress -notlike '169.254*' } | Select-Object -First 1).IPAddress
    Say "--- WAN: default route on ifIdx=$($route.ifIndex) addr=$WanAddress"
}
if (-not $lanIp -or -not $WanAddress) { Say 'ABORT: LAN or WAN address not readable; no run started, no rule touched.'; return }

Say ''
Say '=== run 1: the console close (taskkill without /F) - this is the path the fix is for ==='
Invoke-Run 'close' 'close' | Out-Null
$after1 = Counts
Say "--- run 1 ended with: $after1"

# Run 2 has to start from an empty store: each program refuses to claim a rule it finds already there, so a
# residue from run 1 would make the control measure nothing.
if (-not (Released $after1)) {
    Say '--- run 1 left residue (the close did NOT release it); clearing it so run 2 starts from zero'
    foreach ($n in $names) { if ((Count $n) -ge 1) { Remove-NetFirewallRule -DisplayName $n -ErrorAction Continue } }
    Say "--- cleared: $(Counts)"
}

Say ''
Say '=== run 2: the control, taskkill /F - expected to strand the rules, which is what makes run 1 attributable ==='
Invoke-Run 'force' 'force' | Out-Null
$after2 = Counts
Say "--- run 2 ended with: $after2"

Say ''
Say '--- revert: removing what run 2 stranded, and stopping the AP if this script started it'
foreach ($n in $names) {
    if ((Count $n) -ge 1) { Remove-NetFirewallRule -DisplayName $n -ErrorAction Continue; Say "removed $n" }
}
Say "--- after revert: $(Counts)"
if ($startedAp) { Say((netsh wlan stop hostednetwork | Out-String).Trim()) }

Say ''
Say '=== VERDICT (read these lines and send them) ==='
Say "close-released: run 1 left $(if (Released $after1) { 'every rule of this shape OUT of the store' } else { "residue: $after1" })"
Say "force-control:  run 2 left $after2  (residue here is expected and is the point of the control)"
Say "final store: $(Counts)"
