param([int]$TargetPid, [string]$Needle = 'NODE_EXTRA_CA_CERTS', [string]$Dump)

Add-Type -Namespace Proc -Name EnvScan2 -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool ReadProcessMemory(IntPtr h, IntPtr remoteAddr, byte[] buffer, int size, out int read);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr h);
[DllImport("ntdll.dll")]
public static extern int NtQueryInformationProcess(IntPtr h, int info, byte[] outBuffer, int len, out int retLen);
'@

function Read-At([IntPtr]$h, [long]$addr, [int]$len) {
    $b = New-Object byte[] $len
    $read = 0
    if (-not [Proc.EnvScan2]::ReadProcessMemory($h, [IntPtr]$addr, $b, $len, [ref]$read)) { return $null }
    if ($read -ne $len) { return $null }
    return ,$b
}

# Read up to $max bytes in small chunks, stopping at the first UTF-16 double-NUL that follows
# at least one entry. A single big ReadProcessMemory fails on any uncommitted gap, which is
# exactly what killed the earlier offset-based readers.
function Read-EnvBlock([IntPtr]$h, [long]$addr) {
    $chunk = 512
    $acc = New-Object 'System.Collections.Generic.List[byte]'
    $pos = $addr
    for ($i = 0; $i -lt 512; $i++) {
        $b = Read-At $h $pos $chunk
        if ($null -eq $b) {
            $ok = $false
            for ($tail = 256; $tail -ge 2; $tail /= 2) {
                $b = Read-At $h $pos $tail
                if ($null -ne $b) { $chunk = $tail; $ok = $true; break }
            }
            if (-not $ok) { break }
        }
        for ($k = 0; $k -lt $b.Length; $k++) { $acc.Add($b[$k]) }
        $pos += $b.Length
        if ($b.Length -lt $chunk) { break }
        $arr = $acc.ToArray()
        for ($k = 0; $k -lt $arr.Length - 3; $k++) {
            if ($arr[$k] -eq 0 -and $arr[$k + 1] -eq 0 -and $arr[$k + 2] -eq 0 -and $arr[$k + 3] -eq 0) {
                if ($k -gt 4) {
                    $trimmed = New-Object byte[] ($k)
                    [Array]::Copy($arr, 0, $trimmed, 0, $k)
                    return ,$trimmed
                }
            }
        }
        if ($acc.Count -gt 400000) { break }
    }
    $arr = $acc.ToArray()
    if ($arr.Length -lt 8) { return $null }
    return ,$arr
}

function Score([byte[]]$raw) {
    if ($null -eq $raw) { return $null }
    $txt = [System.Text.Encoding]::Unicode.GetString($raw)
    $ents = @($txt -split "`0" | Where-Object { $_.Length -gt 0 })
    if ($ents.Count -lt 5) { return $null }
    $good = @($ents | Where-Object { $_ -match '^[A-Za-z0-9_+/()\\\. -]+=.*$' }).Count
    if ($good -lt 5 -or $good -lt $ents.Count * 0.9) { return $null }
    if (-not ($txt -match 'SYSTEMROOT=')) { return $null }
    return [pscustomobject]@{ ents = $ents; good = $good; raw = $raw }
}

$h = [Proc.EnvScan2]::OpenProcess(0x1010, $false, $TargetPid)
if ($h -eq [IntPtr]::Zero) { 'OpenProcess failed err=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error(); return }
try {
    $basic = New-Object byte[] 48
    $ret = 0
    [void][Proc.EnvScan2]::NtQueryInformationProcess($h, 0, $basic, 48, [ref]$ret)
    $peb = [BitConverter]::ToInt64($basic, 8)
    $pb = Read-At $h ($peb + 0x20) 8
    if ($null -eq $pb) { 'read PEB+0x20 failed'; return }
    $params = [BitConverter]::ToInt64($pb, 0)
    $win = Read-At $h $params 0x100
    if ($null -eq $win) { 'read params window failed'; return }

    $best = $null
    for ($o = 0; $o -lt 0x100; $o += 8) {
        $v = [BitConverter]::ToInt64($win, $o)
        if ($v -lt 0x10000 -or $v -gt 0x7FFFFFFFFFFF) { continue }
        $s = Score (Read-EnvBlock $h $v)
        if ($null -ne $s) {
            if ($null -eq $best -or $s.good -gt $best.score.good) {
                $best = [pscustomobject]@{ off = $o; score = $s }
            }
        }
    }

    if ($null -eq $best) { 'no env block found at any params pointer 0x00..0xF8'; return }

    $raw = $best.score.raw
    $nb = [System.Text.Encoding]::Unicode.GetBytes($Needle)
    $hexNeedle = ($nb | ForEach-Object { '{0:X2}' -f $_ }) -join ''
    $hexRaw = ($raw | ForEach-Object { '{0:X2}' -f $_ }) -join ''

    'pid          = ' + $TargetPid
    'block        = params+0x' + ('{0:X2}' -f $best.off) + '   bytes=' + $raw.Length + '   entries=' + $best.score.ents.Count
    $nodeHits = @($best.score.ents | Where-Object { $_ -like 'NODE_*' })
    $appHits = @($best.score.ents | Where-Object { $_ -match '^(QODER|ELECTRON)' })
    'raw contains ' + $Needle + ' = ' + $hexRaw.Contains($hexNeedle)
    'NODE entries = ' + ($nodeHits -join ' | ')
    'app entries  = ' + ($appHits -join ' | ')
    'first        = ' + $best.score.ents[0]
    'last         = ' + $best.score.ents[-1]
    if ($Dump) { Set-Content -Path $Dump -Value ($best.score.ents | ForEach-Object { ($_ -split '=')[0] }) -Encoding utf8 }
} finally {
    [void][Proc.EnvScan2]::CloseHandle($h)
}
