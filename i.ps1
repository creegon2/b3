# b3 bootstrap for blue-zone PC #3.
# Typed by the user in an admin PowerShell:  irm https://raw.githubusercontent.com/creegon2/b3/main/i.ps1|iex
# 1) probes the network and prints a short table, 2) turns off AC sleep,
# 3) installs scheduled tasks that fetch stage2.ps1 from this repo every 5 minutes and run it once per new version.
& {
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$Relay = '106.15.130.93'
$Test = [bool]$env:B3_TEST
$Root = if ($Test) { 'C:\ProgramData\b3test' } else { 'C:\ProgramData\b3' }
$Prefix = if ($Test) { 'b3test' } else { 'b3' }

function Say([string]$t, [string]$c = 'Gray') { Write-Host $t -ForegroundColor $c }

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Say '没有管理员权限：请右键 PowerShell，选「以管理员身份运行」，再敲一次同一行命令。' 'Red'
    return
}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
New-Item -ItemType Directory -Force -Path $Root | Out-Null
Say '正在检测网络，约 1 分钟……' 'Cyan'

# ---------- proxy discovery ----------
$proxies = New-Object System.Collections.Generic.List[string]
function Add-Proxy([string]$p) {
    if (-not $p) { return }
    $p = $p.Trim().TrimEnd('/')
    if (-not $p) { return }
    if ($p -notmatch '^[a-zA-Z0-9]+://') { $p = 'http://' + $p }
    if (-not $proxies.Contains($p)) { $proxies.Add($p) }
}
$ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
if ($ie -and $ie.ProxyServer) {
    foreach ($part in ($ie.ProxyServer -split ';')) {
        if ($part -match '=') {
            $kv = $part -split '=', 2
            if ($kv[0] -match '^(?i)(http|https)$') { Add-Proxy $kv[1] }
            elseif ($kv[0] -match '^(?i)socks$') { Add-Proxy ('socks5://' + $kv[1]) }
        } else { Add-Proxy $part }
    }
}
$sysProxy = [System.Net.WebRequest]::GetSystemWebProxy()
$resolved = [ordered]@{}
foreach ($u in @('https://raw.githubusercontent.com/', "https://${Relay}/", "http://${Relay}/")) {
    try {
        $r = $sysProxy.GetProxy([uri]$u).AbsoluteUri
        $resolved[$u] = $r
        if ($r -and ($r.TrimEnd('/') -ne $u.TrimEnd('/'))) { Add-Proxy $r }
    } catch { $resolved[$u] = 'ERR ' + $_.Exception.Message }
}
$winhttp = ((netsh winhttp show proxy) -join ' ')
foreach ($m in [regex]::Matches($winhttp, '([A-Za-z0-9][A-Za-z0-9\.\-]*:\d{2,5})')) { Add-Proxy $m.Groups[1].Value }
$envProxy = [ordered]@{}
foreach ($n in @('HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY')) {
    foreach ($scope in @('Process', 'User', 'Machine')) {
        $v = [Environment]::GetEnvironmentVariable($n, $scope)
        if ($v) { $envProxy["$scope.$n"] = $v; Add-Proxy $v }
    }
}
$skipProc = @('System', 'svchost', 'lsass', 'wininit', 'services', 'spoolsv', 'Idle', 'sshd', 'jhi_service', 'LMS')
$listeners = @()
try {
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
        Where-Object { $_.LocalAddress -in @('127.0.0.1', '0.0.0.0', '::1', '::') } |
        ForEach-Object {
            $pn = ''
            try { $pn = (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName } catch {}
            [pscustomobject]@{ Port = $_.LocalPort; Process = $pn }
        } | Where-Object { $_.Process -and ($skipProc -notcontains $_.Process) } |
        Sort-Object Port -Unique | Select-Object -First 20)
} catch {}
$localCandidates = @()
foreach ($l in $listeners) {
    $localCandidates += ('http://127.0.0.1:' + $l.Port)
    $localCandidates += ('socks5://127.0.0.1:' + $l.Port)
}

# ---------- probes ----------
function Open-Tcp([string]$h, [int]$p, [int]$ms) {
    $c = New-Object System.Net.Sockets.TcpClient
    $ar = $c.BeginConnect($h, $p, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne($ms)) { $c.Close(); throw '连接超时' }
    $c.EndConnect($ar)
    return $c
}
function Read-Some($s, [int]$ms) {
    $s.ReadTimeout = $ms
    $buf = New-Object byte[] 1024
    $n = $s.Read($buf, 0, $buf.Length)
    if ($n -le 0) { return '' }
    return [Text.Encoding]::ASCII.GetString($buf, 0, $n)
}
function Test-Ssh([string]$target, [int]$port, [string]$proxy) {
    $c = $null
    try {
        if (-not $proxy) {
            $c = Open-Tcp $target $port 4000
            $s = $c.GetStream()
        } else {
            $u = [uri]$proxy
            $c = Open-Tcp $u.Host $u.Port 3000
            $s = $c.GetStream()
            if ($u.Scheme -like 'socks*') {
                $s.Write([byte[]](5, 1, 0), 0, 3)
                $s.ReadTimeout = 4000
                $b = New-Object byte[] 2
                $n = $s.Read($b, 0, 2)
                if ($n -lt 2 -or $b[0] -ne 5 -or $b[1] -ne 0) { throw '不是 SOCKS5' }
                $hb = [Text.Encoding]::ASCII.GetBytes($target)
                $req = [byte[]](@(5, 1, 0, 3, $hb.Length) + $hb + @([byte]($port -shr 8), [byte]($port -band 255)))
                $s.Write($req, 0, $req.Length)
                $r = New-Object byte[] 512
                $n = $s.Read($r, 0, 512)
                if ($n -lt 2 -or $r[1] -ne 0) { throw ('SOCKS5 拒绝，代码 ' + $r[1]) }
            } else {
                $q = [Text.Encoding]::ASCII.GetBytes("CONNECT ${target}:$port HTTP/1.1`r`nHost: ${target}:$port`r`n`r`n")
                $s.Write($q, 0, $q.Length)
                $resp = ''
                $sw = [Diagnostics.Stopwatch]::StartNew()
                while (($resp -notmatch "`r`n`r`n") -and ($sw.ElapsedMilliseconds -lt 8000)) {
                    $t = Read-Some $s 8000
                    if (-not $t) { break }
                    $resp += $t
                }
                $first = ($resp -split "`r`n")[0]
                if ($first -notmatch '^HTTP/\S+\s+200') { throw ('代理回复：' + $first) }
                $rest = $resp.Substring($resp.IndexOf("`r`n`r`n") + 4)
                if ($rest -match '^SSH-') { return ('通 ' + ($rest -split "`r?`n")[0]) }
            }
        }
        $banner = Read-Some $s 6000
        if ($banner -match '^SSH-') { return ('通 ' + ($banner -split "`r?`n")[0]) }
        return ('连上但不是 ssh：' + $banner.Substring(0, [Math]::Min(30, $banner.Length)))
    } catch {
        $msg = $_.Exception.Message
        if ($_.Exception.InnerException) { $msg = $_.Exception.InnerException.Message }
        return ('不通：' + $msg)
    } finally { if ($c) { try { $c.Close() } catch {} } }
}
function Test-Http([string]$u, [bool]$direct) {
    try {
        $req = [Net.HttpWebRequest]::Create($u)
        $req.Timeout = 10000
        if ($direct) { $req.Proxy = $null } elseif ($req.Proxy) { $req.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials }
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Close()
        return ('通 ' + $code)
    } catch { return ('不通：' + $_.Exception.Message) }
}

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row([string]$what, [string]$res) { $rows.Add([pscustomobject]@{ What = $what; Result = $res }) }
Add-Row 'GitHub 按系统设置' (Test-Http 'https://raw.githubusercontent.com/creegon2/b3/main/stage2.ps1' $false)
Add-Row 'GitHub 不走代理' (Test-Http 'https://raw.githubusercontent.com/creegon2/b3/main/stage2.ps1' $true)
foreach ($p in @(443, 80, 3389, 22)) { Add-Row "中转 直连 $p" (Test-Ssh $Relay $p '') }
Add-Row 'github.com 直连 22' (Test-Ssh 'github.com' 22 '')
Add-Row 'ssh.github.com 直连 443' (Test-Ssh 'ssh.github.com' 443 '')
foreach ($px in $proxies) {
    foreach ($p in @(443, 22)) { Add-Row "中转 经 $px 到 $p" (Test-Ssh $Relay $p $px) }
}
$localTried = 0; $localOk = 0
foreach ($px in $localCandidates) {
    if ($proxies.Contains($px)) { continue }
    $localTried++
    $r = Test-Ssh $Relay 22 $px
    if ($r -like '通*') { $localOk++; Add-Row "中转 经 $px 到 22" $r; Add-Proxy $px }
}
Add-Row '本机其他监听端口当代理试' ("试了 $localTried 个，通 $localOk 个")

# ---------- machine info ----------
$info = [ordered]@{
    Time = (Get-Date).ToString('o'); Computer = $env:COMPUTERNAME; User = "$env:USERDOMAIN\$env:USERNAME"
    IE = [ordered]@{ ProxyEnable = $ie.ProxyEnable; ProxyServer = $ie.ProxyServer; AutoConfigURL = $ie.AutoConfigURL; ProxyOverride = $ie.ProxyOverride }
    Resolved = $resolved; WinHttp = $winhttp; Env = $envProxy; Listeners = $listeners; Proxies = $proxies.ToArray()
    Probe = $rows.ToArray()
}
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $info.OS = "$($os.Caption) $($os.Version)"
    $info.RAMGB = [Math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
    $info.CPU = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    $info.Domain = if ($cs.PartOfDomain) { $cs.Domain } else { '' }
    $info.Disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID) free $([Math]::Round($_.FreeSpace/1GB))G of $([Math]::Round($_.Size/1GB))G" })
} catch {}
$info.SshServices = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*ssh*' } | ForEach-Object { "$($_.Name) $($_.Status)" })
$info | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Root 'probe.json') -Encoding UTF8
[ordered]@{ Proxies = $proxies.ToArray() } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'net.json') -Encoding UTF8

# ---------- poller ----------
$poll = @'
param([string]$Root = '__ROOT__')
$ErrorActionPreference = 'Continue'
$log = Join-Path $Root 'poll.log'
function L([string]$m) { try { Add-Content -LiteralPath $log -Encoding UTF8 -Value ('{0:o} [{1}] {2}' -f (Get-Date), $env:USERNAME, $m) } catch {} }
$lock = $null
try { $lock = [IO.File]::Open((Join-Path $Root 'poll.lock'), 'OpenOrCreate', 'ReadWrite', 'None') } catch { return }
try {
    if ((Test-Path -LiteralPath $log) -and ((Get-Item -LiteralPath $log).Length -gt 1MB)) { Move-Item -LiteralPath $log -Destination ($log + '.previous') -Force }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
    $net = $null
    try { $net = Get-Content -LiteralPath (Join-Path $Root 'net.json') -Raw | ConvertFrom-Json } catch {}
    $routes = @('SYSTEM', 'DIRECT')
    if ($net -and $net.Proxies) { $routes += @($net.Proxies | Where-Object { $_ -like 'http*' }) }
    $urls = @('https://raw.githubusercontent.com/creegon2/b3/main/stage2.ps1', 'https://github.com/creegon2/b3/raw/main/stage2.ps1')
    $body = $null; $via = ''
    foreach ($u in $urls) {
        foreach ($r in $routes) {
            try {
                $wc = New-Object System.Net.WebClient
                $wc.Encoding = [Text.Encoding]::UTF8
                if ($r -eq 'DIRECT') { $wc.Proxy = $null }
                elseif ($r -ne 'SYSTEM') { $p = New-Object System.Net.WebProxy($r); $p.UseDefaultCredentials = $true; $wc.Proxy = $p }
                elseif ($wc.Proxy) { $wc.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials }
                $wc.Headers['Cache-Control'] = 'no-cache'
                $body = $wc.DownloadString($u)
                if ($body) { $via = "$u via $r"; break }
            } catch { L ("fetch failed: $u via $r : " + $_.Exception.Message) }
        }
        if ($body) { break }
    }
    if (-not $body) { L 'no route to GitHub this round'; return }
    $first = ($body -split "`n")[0].Trim()
    if ($first -like '#b3-wait*') { L "waiting ($via)"; return }
    $sha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($body))).Replace('-', '')
    $appliedFile = Join-Path $Root 'applied.sha256'
    if ((Test-Path -LiteralPath $appliedFile) -and ((Get-Content -LiteralPath $appliedFile -Raw).Trim() -eq $sha)) { return }
    $stage = Join-Path $Root 'stage2.ps1'
    [IO.File]::WriteAllText($stage, $body, (New-Object System.Text.UTF8Encoding($true)))
    L "running stage2 $sha ($via)"
    $out = Join-Path $Root ('stage2-' + $env:USERNAME + '.log')
    & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $stage -B3Root $Root *>> $out
    $code = $LASTEXITCODE
    L "stage2 exit $code"
    if ($code -eq 0) { Set-Content -LiteralPath $appliedFile -Value $sha -Encoding ASCII }
} finally { if ($lock) { $lock.Close() } }
'@
$poll = $poll.Replace('__ROOT__', $Root)
[IO.File]::WriteAllText((Join-Path $Root 'poll.ps1'), $poll, (New-Object System.Text.UTF8Encoding($true)))

$taskState = ''
try {
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $psArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $Root 'poll.ps1') + '"'
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -Hidden
    $trig = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)))
    $sysP = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "$Prefix-poll-system" -Action (New-ScheduledTaskAction -Execute $ps -Argument $psArgs) -Trigger $trig -Principal $sysP -Settings $set -Force -ErrorAction Stop | Out-Null
    $conhost = Join-Path $env:SystemRoot 'System32\conhost.exe'
    $usrP = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
    $trig2 = @((New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 5)))
    Register-ScheduledTask -TaskName "$Prefix-poll-user" -Action (New-ScheduledTaskAction -Execute $conhost -Argument ('--headless "' + $ps + '" ' + $psArgs)) -Trigger $trig2 -Principal $usrP -Settings $set -Force -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName "$Prefix-poll-system"
    $taskState = '已装好，每 5 分钟检查一次'
} catch { $taskState = '安装失败：' + $_.Exception.Message }

if (-not $Test) {
    powercfg /change standby-timeout-ac 0 | Out-Null
    powercfg /change hibernate-timeout-ac 0 | Out-Null
}

Write-Host ''
Say '======== 结果（请截图发回） ========' 'Yellow'
Say ("电脑 $env:COMPUTERNAME   用户 $env:USERDOMAIN\$env:USERNAME   管理员 是") 'White'
foreach ($r in $rows) {
    $color = if ($r.Result -like '通*') { 'Green' } else { 'DarkGray' }
    Say ('{0,-34} {1}' -f $r.What, $r.Result) $color
}
Say ('后台任务：' + $taskState) $(if ($taskState -like '已装好*') { 'Green' } else { 'Red' })
Say ('完整记录：' + (Join-Path $Root 'probe.json')) 'Gray'
if ($taskState -like '已装好*') { Say '这一步完成了，可以走了。之后的安装会自动进行。' 'Green' }
}
