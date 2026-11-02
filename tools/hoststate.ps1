# The live state a run has to be judged against, read from outside it. Both programs' own verdict lines are
# only half the evidence: an elevated run's console may show nothing at all, and a firewall rule's owner is
# the store rather than the process that added it. This is what to run immediately before a hand-over and
# immediately after it, so the two counts are the witness and the log's last line is not.
$ErrorActionPreference = 'Continue'
Write-Output "=== rules named by this repo ==="
foreach ($n in 'tlsmitm-relay-in','router-lan-in','router-dns-tcp-in') {
  $c = (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Measure-Object).Count
  Write-Output "$n = $c"
}
Write-Output "=== SharedAccess / icssvc ==="
foreach ($s in 'SharedAccess','icssvc') { Write-Output "$s = $((Get-Service $s -ErrorAction SilentlyContinue).Status)" }
Write-Output "=== adapters that are Up ==="
Get-NetAdapter | Where-Object Status -eq 'Up' | Format-Table ifIndex, Name, Status -AutoSize | Out-String -Width 200
Write-Output "=== ipv4 addresses ==="
Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254*' -and $_.IPAddress -ne '127.0.0.1' } |
  Sort-Object ifIndex | Format-Table ifIndex, InterfaceAlias, IPAddress, PrefixLength, SuffixOrigin -AutoSize | Out-String -Width 200
Write-Output "=== default routes ==="
Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
  Sort-Object RouteMetric | Format-Table ifIndex, NextHop, RouteMetric -AutoSize | Out-String -Width 200
Write-Output "=== repo processes ==="
Get-CimInstance Win32_Process -Filter 'Name="Router.exe" OR Name="TlsMitm.exe" OR Name="apcheck.exe"' |
  ForEach-Object { Write-Output "pid=$($_.ProcessId) $($_.Name)" }
Write-Output "=== hosted network ==="
# Selected, never the whole output, and never `show hostednetwork setting=security`: that verb prints the
# passphrase in plaintext, and a transcript of this script is something people paste.
netsh wlan show hostednetwork | Select-String -Pattern 'Status|BSSID|Channel|SSID number|Number of clients'
