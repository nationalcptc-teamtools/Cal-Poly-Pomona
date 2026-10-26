# btct.ps1: a command-line menu for running BTCT on Windows (Docker Desktop).
#
# The Windows twin of btct.sh, with the same subcommands. Run it with no
# arguments for a numbered menu, or with a subcommand:
#
#   .\btct.ps1                        the menu
#   .\btct.ps1 status                 health, container, URLs, RAM/CPU, backup folder, last backup
#   .\btct.ps1 start | stop | restart
#   .\btct.ps1 backup-dir [PATH]      set the folder backups go to, recreate btct, verify it
#   .\btct.ps1 backup-dir --show      print the folder .env names and the one the container mounts
#   .\btct.ps1 backup                 run a backup now (admin login or BTCT_BACKUP_TOKEN)
#   .\btct.ps1 backups                list backups (from the server when logged in, else the folder)
#   .\btct.ps1 schedule [on|off] [--every MIN] [--keep N] [--show]
#   .\btct.ps1 restore [NAME] [--keep-browser-caches] [--partial]
#   .\btct.ps1 passwords              print /data/initial-passwords.txt (secrets)
#   .\btct.ps1 logs [-f] [LINES]
#   .\btct.ps1 update [-Branch NAME] [-Rebuild]
#                                     pull the latest comp-ready (or NAME), build the new image
#                                     while BTCT runs, stop, snapshot the data volume to
#                                     <backup folder>\pre-update-<stamp>.tgz, start, wait for health
#   .\btct.ps1 rollback [-Data] [SNAPSHOT]
#                                     run the image from before the last update again
#                                     (<image>:previous); -Data also puts back a pre-update snapshot
#   .\btct.ps1 check                  Docker, compose project, port and health in one look
#   .\btct.ps1 install | uninstall    the `btct` function in your PowerShell profile
#   .\btct.ps1 help
#
# After `.\btct.ps1 install`, open a new PowerShell and type `btct`.
# -y / --yes / -Yes answers yes to confirmations. It reuses Start-BTCT.ps1
# (start), Choose-BackupFolder.ps1 (the folder picker and the .env line),
# Backup-BTCT.ps1 (backup now) and Restore-BTCT.ps1 (verify and restore).
#
# Environment: BTCT_USER (default Roberto), BTCT_PASSWORD (for scripts),
# BTCT_BACKUP_TOKEN, BTCT_PROJECT (compose project), BTCT_CONTAINER (container
# name, default btct), BTCT_HEALTH_TIMEOUT (180).

$ErrorActionPreference = 'Stop'
$RepoPath = Split-Path -Parent $PSCommandPath
$SelfPath = $PSCommandPath
$EnvFile = Join-Path $RepoPath '.env'
$CName = 'btct'
if ($env:BTCT_CONTAINER) { $CName = $env:BTCT_CONTAINER }
$AliasMark = '# btct-cli'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$HealthTimeout = 180
if ($env:BTCT_HEALTH_TIMEOUT) { $HealthTimeout = [int]$env:BTCT_HEALTH_TIMEOUT }
$script:AssumeYes = $false
$script:SessionToken = ''
$script:Project = ''
$script:ProjectFrom = ''
$script:Port = ''

function Write-Info([string] $m) { Write-Host "[btct] $m" -ForegroundColor Cyan }
function Write-Ok([string] $m)   { Write-Host "[btct] $m" -ForegroundColor Green }
function Write-Warn([string] $m) { Write-Host "[btct] $m" -ForegroundColor Yellow }
function Write-Err([string] $m)  { Write-Host "[btct] $m" -ForegroundColor Red }
function Write-Row([string] $k, [string] $v) { Write-Host ('  {0,-13} {1}' -f $k, $v) }

function Test-Interactive {
    if ($env:BTCT_NO_PROMPT) { return $false }
    if ([Environment]::GetCommandLineArgs() -match '^-NonI') { return $false }
    return [Environment]::UserInteractive
}

function Confirm-Step([string] $question, [bool] $default) {
    if ($script:AssumeYes) { return $true }
    if (-not (Test-Interactive)) { return $default }
    $hint = '[y/N]'; if ($default) { $hint = '[Y/n]' }
    $a = Read-Host "$question $hint"
    if ($a -match '^(y|yes)$') { return $true }
    if ($a -match '^(n|no)$') { return $false }
    return $default
}

# ── .env ────────────────────────────────────────────────────────────────
function Get-EnvValue([string] $key) {
    # The last KEY= line wins, as in docker compose; one pair of quotes is stripped.
    if (-not (Test-Path -LiteralPath $EnvFile)) { return '' }
    $value = ''
    foreach ($l in [System.IO.File]::ReadAllLines($EnvFile, $Utf8NoBom)) {
        if ($l.StartsWith("$key=")) { $value = $l.Substring($key.Length + 1).TrimEnd("`r").Trim() }
    }
    if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    return $value
}

function Resolve-BackupDir([string] $v) {
    if (-not $v) { return (Join-Path $RepoPath 'backups') }
    if ([System.IO.Path]::IsPathRooted($v)) { return $v }
    return (Join-Path $RepoPath ($v -replace '^\.[\\/]', ''))
}
function Get-BackupDir { return (Resolve-BackupDir (Get-EnvValue 'BACKUP_HOST_DIR')) }

function Get-FreeText([string] $p) {
    try {
        $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($p))
        $b = ([System.IO.DriveInfo]::new($root)).AvailableFreeSpace
        return ('{0:N1} GB free' -f ($b / 1GB))
    } catch { return 'free space unknown' }
}

function Format-Size([double] $b) {
    if ($b -ge 1GB) { return ('{0:N2} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
    return ('{0:N0} KB' -f ($b / 1KB))
}

# ── Docker and compose ──────────────────────────────────────────────────
function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Err "Docker CLI not found on PATH. Install Docker Desktop for Windows first."
        return $false
    }
    $null = & docker info 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Docker is not answering. Start Docker Desktop (or run: btct start, which starts it)."
        return $false
    }
    Find-Project
    return $true
}

# The compose project of the running BTCT: the btct container's label, else
# COMPOSE_PROJECT_NAME from .env, else compose's default (the folder name).
# It goes into COMPOSE_PROJECT_NAME for this process, so Start-BTCT.ps1 and
# Restore-BTCT.ps1, which run plain `docker compose`, use it too.
function Find-Project {
    if ($script:ProjectFrom) { return }
    $p = ''; $from = ''
    if ($env:BTCT_PROJECT) { $p = $env:BTCT_PROJECT; $from = 'BTCT_PROJECT' }
    else {
        $lbl = (& docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' $CName 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $lbl -and $lbl -ne '<no value>') { $p = $lbl; $from = "the $CName container's label" }
        elseif (Get-EnvValue 'COMPOSE_PROJECT_NAME') { $p = Get-EnvValue 'COMPOSE_PROJECT_NAME'; $from = 'COMPOSE_PROJECT_NAME in .env' }
    }
    if ($p) {
        $env:COMPOSE_PROJECT_NAME = $p
    } else {
        $p = ((Split-Path -Leaf $RepoPath).ToLower() -replace '[^a-z0-9_-]', '')
        $from = 'compose default (the folder name)'
    }
    $script:Project = $p; $script:ProjectFrom = $from
}

function Invoke-Compose {
    Push-Location $RepoPath
    try { & docker compose @args } finally { Pop-Location }
}

function Test-Exists { $null = & docker inspect $CName 2>$null; return ($LASTEXITCODE -eq 0) }
function Test-Running { return ((& docker inspect -f '{{.State.Running}}' $CName 2>$null | Out-String).Trim() -eq 'true') }
function Get-MountSource {
    return (& docker inspect -f '{{range .Mounts}}{{if eq .Destination "/backups"}}{{.Source}}{{end}}{{end}}' $CName 2>$null | Out-String).Trim()
}

function Get-HostPort {
    if ($script:Port) { return $script:Port }
    $p = ''
    if (Test-Running) {
        $line = (Invoke-Compose port btct 8080 2>$null | Select-Object -Last 1)
        if ($line -match ':(\d+)\s*$') { $p = $Matches[1] }
    }
    if (-not $p) {
        foreach ($f in @('docker-compose.yml', 'docker-compose.override.yml')) {
            $path = Join-Path $RepoPath $f
            if (Test-Path -LiteralPath $path) {
                foreach ($l in [System.IO.File]::ReadAllLines($path)) {
                    if ($l -match '^\s*-\s*"?(?:[0-9.]+:)?(\d+):8080"?\s*$') { $p = $Matches[1] }
                }
            }
        }
    }
    if (-not $p) { $p = '8080' }
    $script:Port = $p
    return $p
}
# 127.0.0.1, not localhost: on a WSL2 Docker host localhost can hang (README "Running on Windows").
function Get-BaseUrl { return "http://127.0.0.1:$(Get-HostPort)" }

function Test-Healthy {
    try {
        $r = Invoke-WebRequest -Uri "$(Get-BaseUrl)/healthz" -UseBasicParsing -TimeoutSec 3
        return ($r.StatusCode -eq 200)
    } catch { return $false }
}

function Wait-Healthy {
    Write-Info "waiting for $(Get-BaseUrl)/healthz (up to ${HealthTimeout}s)"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $HealthTimeout) {
        if (Test-Healthy) { Write-Ok "BTCT is up and healthy after $([int]$sw.Elapsed.TotalSeconds)s"; return $true }
        Start-Sleep -Seconds 2
    }
    Write-Err "/healthz did not answer within ${HealthTimeout}s; last log lines:"
    Invoke-Compose logs --tail=30 btct | Out-Host
    return $false
}

# ── The admin API ───────────────────────────────────────────────────────
function Invoke-Login {
    if (-not (Test-Running)) { Write-Err 'BTCT is not running (btct start)'; return $false }
    for ($i = 0; $i -lt 3; $i++) {
        $user = $env:BTCT_USER; if (-not $user) { $user = 'Roberto' }
        if ($env:BTCT_PASSWORD) { $pass = $env:BTCT_PASSWORD }
        else {
            if (-not (Test-Interactive)) { Write-Err 'logging in needs a console; or set BTCT_BACKUP_TOKEN (Admin panel -> Backups) for backup and status'; return $false }
            $u = Read-Host "BTCT admin username [$user]"
            if ($u) { $user = $u }
            $sec = Read-Host "Password for $user" -AsSecureString
            $pass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
        }
        try {
            $body = @{ username = $user; password = $pass } | ConvertTo-Json -Compress
            $r = Invoke-RestMethod -Method Post -Uri "$(Get-BaseUrl)/api/login" -Body $body -ContentType 'application/json' -TimeoutSec 15
            $pass = $null
            $script:SessionToken = $r.token
            if (-not $r.user.isAdmin) { Write-Warn "$user is not an admin; backup actions need an admin account" }
            Write-Ok "logged in as $user (kept in memory for this run only)"
            return $true
        } catch {
            $pass = $null
            Write-Err "login failed: $($_.ErrorDetails.Message)$($_.Exception.Message)"
            if ($env:BTCT_PASSWORD) { return $false }
        }
    }
    return $false
}

# Token for a route: "token" routes (status, run) accept BTCT_BACKUP_TOKEN.
function Get-AuthToken([string] $kind) {
    if ($script:SessionToken) { return $script:SessionToken }
    if ($kind -eq 'token' -and $env:BTCT_BACKUP_TOKEN) { return $env:BTCT_BACKUP_TOKEN }
    if (Invoke-Login) { return $script:SessionToken }
    return $null
}

function Invoke-Api([string] $kind, [string] $method, [string] $path, $body = $null) {
    $tok = Get-AuthToken $kind
    if (-not $tok) { throw 'not logged in' }
    $p = @{ Method = $method; Uri = "$(Get-BaseUrl)$path"; Headers = @{ Authorization = "Bearer $tok" }; TimeoutSec = 3600 }
    if ($null -ne $body) { $p.Body = ($body | ConvertTo-Json -Compress); $p.ContentType = 'application/json' }
    try { return Invoke-RestMethod @p }
    catch {
        $code = 0
        try { $code = [int]$_.Exception.Response.StatusCode } catch { }
        if ($code -eq 401 -and $tok -eq $script:SessionToken) {
            $script:SessionToken = ''
            Write-Info 'the session was refused; log in again'
            if (-not (Invoke-Login)) { throw }
            $p.Headers = @{ Authorization = "Bearer $($script:SessionToken)" }
            return Invoke-RestMethod @p
        }
        throw
    }
}

function Format-When($t) {
    if (-not $t) { return 'never' }
    return ([DateTimeOffset]::FromUnixTimeMilliseconds([int64]$t)).LocalDateTime.ToString('yyyy-MM-dd HH:mm')
}
function Format-Schedule($c) {
    $s = 'off'; if ($c.enabled) { $s = "on, every $($c.fullIntervalMin) min" }
    $k = $c.keepLast; if (-not $k) { $k = 'all' }
    return "$s, keep last $k"
}

# ── Commands ────────────────────────────────────────────────────────────
function Invoke-Status {
    if (-not (Test-Docker)) { return }
    $port = Get-HostPort
    Write-Host 'BTCT status' -ForegroundColor White
    Write-Row 'checkout' "$RepoPath (compose project '$($script:Project)', from $($script:ProjectFrom))"
    if (Test-Exists) {
        $st = (& docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}|{{.State.StartedAt}}|{{.Config.Image}}' $CName | Out-String).Trim().Split('|')
        if ($st[0] -eq 'running') {
            $up = ''
            try { $d = (Get-Date) - [DateTime]::Parse($st[2]); $up = ('{0}d {1}h {2}m' -f $d.Days, $d.Hours, $d.Minutes) } catch { }
            Write-Row 'container' "running, $($st[1]), up $up (image $($st[3]))"
        } else { Write-Row 'container' "$($st[0]) (image $($st[3])). Start it with: btct start" }
    } else { Write-Row 'container' 'not created yet. Start it with: btct start' }
    if (Test-Running) {
        $h = ''
        try { $h = (Invoke-WebRequest -Uri "$(Get-BaseUrl)/healthz" -UseBasicParsing -TimeoutSec 3).Content } catch { $h = "no answer on 127.0.0.1:$port" }
        Write-Row 'health' $h
        Write-Row 'open' "http://127.0.0.1:$port"
        if (Get-Command Get-NetIPAddress -ErrorAction SilentlyContinue) {
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.InterfaceAlias -notmatch 'vEthernet|WSL|Loopback|docker' } |
                ForEach-Object { Write-Row '' "http://$($_.IPAddress):$port  (team LAN)" }
        }
        $stats = (& docker stats --no-stream --format '{{.MemUsage}}|{{.CPUPerc}}' $CName 2>$null | Out-String).Trim()
        if ($stats) { $s = $stats.Split('|'); Write-Row 'resources' "RAM $($s[0]), CPU $($s[1])" }
    }
    $dir = Get-BackupDir
    Write-Row 'backups' "$dir ($(Get-FreeText $dir))"
    if ((Test-Exists) -and (Get-MountSource)) { Write-Row '' "the container mounts $(Get-MountSource) at /backups" }
    if ((Test-Running) -and ($script:SessionToken -or $env:BTCT_BACKUP_TOKEN)) {
        try {
            $s = Invoke-Api 'token' 'GET' '/api/backup/status'
            if ($s.lastBackup) { Write-Row 'last backup' "$($s.lastBackup.name), $(Format-Size $s.lastBackup.bytes), $(Format-When $s.lastBackup.at)" }
            else { Write-Row 'last backup' 'none yet' }
            Write-Row 'schedule' (Format-Schedule $s)
        } catch { Write-Err "backup status: $($_.Exception.Message)" }
    } else {
        $newest = Get-ChildItem -LiteralPath $dir -Filter 'btct-backup-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
        $n = 'none in the folder'; if ($newest) { $n = $newest.Name }
        Write-Row 'last backup' "$n (log in, or set BTCT_BACKUP_TOKEN, for the server's view)"
    }
}

function Invoke-Start {
    Find-ProjectQuiet
    try { & (Join-Path $RepoPath 'Start-BTCT.ps1') -NoBrowser -HealthTimeoutSeconds $HealthTimeout } catch { Write-Err $_.Exception.Message }
}
# Start-BTCT.ps1 starts Docker Desktop itself, so the project lookup must not
# fail when Docker is still down.
function Find-ProjectQuiet {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $null = & docker info 2>$null
        if ($LASTEXITCODE -eq 0) { Find-Project }
    }
}

function Invoke-Stop {
    if (-not (Test-Docker)) { return }
    if (-not (Test-Running)) { Write-Info 'BTCT is not running'; return }
    Write-Info 'stopping BTCT (it flushes its data first; up to 60 s)'
    Invoke-Compose stop btct
    if ($LASTEXITCODE -eq 0) { Write-Ok 'stopped' }
}

function Invoke-Restart {
    if (-not (Test-Docker)) { return }
    if (-not (Test-Exists)) { Invoke-Start; return }
    Invoke-Compose restart btct
    $null = Wait-Healthy
}

function Test-BackupMount([string] $want) {
    $ok = $true
    $mnt = Get-MountSource
    $norm = { param($s) ($s -replace '\\', '/').TrimEnd('/').ToLower() }
    # Docker Desktop reports a Windows folder as /run/desktop/mnt/host/c/... or C:\...
    $w = & $norm $want
    $m = & $norm $mnt
    $tail = $w -replace '^([a-z]):', '/$1'
    if ($m -and ($m -eq $w -or $m.EndsWith($tail))) { Write-Ok "the container mounts $mnt at /backups" }
    else { Write-Err "the container mounts '$mnt' at /backups, not $want"; $ok = $false }
    # No double quotes in the argument: Windows PowerShell 5.1 strips them from native arguments.
    & docker exec -u 1000 $CName sh -c 'f=/backups/.btct-write-test.$$ && echo ok > $f && rm -f $f' 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Ok 'write test as uid 1000 in /backups: ok' }
    else { Write-Err "the container cannot write to /backups ($want). Check Docker Desktop file sharing for that drive."; $ok = $false }
    return $ok
}

function Invoke-BackupDir([string[]] $a) {
    $show = $a -contains '--show'
    $path = ($a | Where-Object { $_ -and -not $_.StartsWith('-') } | Select-Object -First 1)
    $cur = Get-BackupDir
    if ($show) {
        Write-Output $cur
        Write-Row 'in .env' "BACKUP_HOST_DIR=$(Get-EnvValue 'BACKUP_HOST_DIR')"
        Write-Row 'free' (Get-FreeText $cur)
        if ((Test-Docker) -and (Test-Exists)) { Write-Row 'mounted' "$(Get-MountSource) -> /backups" }
        return
    }
    $chooser = Join-Path $RepoPath 'Choose-BackupFolder.ps1'
    $prev = $null
    if (Test-Path -LiteralPath $EnvFile) { $prev = [System.IO.File]::ReadAllText($EnvFile, $Utf8NoBom) }
    if (-not $path -and (Test-Interactive)) {
        Write-Host "Current backup folder: $cur ($(Get-FreeText $cur))"
        $path = Read-Host 'New folder (Enter opens the folder picker)'
    }
    if ($path) { & $chooser -Path $path -NoApply } else { & $chooser -NoApply }
    if ($LASTEXITCODE -ne 0) { Write-Err 'the backup folder was not changed'; return }
    $new = Get-BackupDir
    if (-not (Test-Docker)) { Write-Info "start BTCT later and it will write to $new"; return }
    if (-not (Test-Running)) {
        Write-Info "BTCT is not running; it will write to $new when it starts"
        if (Confirm-Step 'Start BTCT now?' $false) { Invoke-Start; $null = Test-BackupMount $new }
        return
    }
    if (-not (Confirm-Step "Recreate the btct container now so it writes to $new? (data is kept; about 10 s offline)" $true)) {
        Write-Info "not applied yet; run 'btct start' when it suits you"; return
    }
    Invoke-Compose up -d
    if ($LASTEXITCODE -eq 0 -and (Wait-Healthy) -and (Test-BackupMount $new)) { Write-Ok "backups now go to $new"; return }
    Write-Err 'the new backup folder did not work'
    if (Confirm-Step "Put the previous folder ($cur) back and recreate the container?" $true) {
        if ($null -ne $prev) { [System.IO.File]::WriteAllText($EnvFile, $prev, $Utf8NoBom) } else { Remove-Item -LiteralPath $EnvFile -Force }
        Invoke-Compose up -d
        if ((Wait-Healthy) -and (Test-BackupMount $cur)) { Write-Ok "back on $cur" }
    }
}

function Invoke-Backup {
    if (-not (Test-Docker)) { return }
    if (-not (Test-Running)) { Write-Err 'BTCT is not running. Start it with: btct start'; return }
    $tok = Get-AuthToken 'token'
    if (-not $tok) { return }
    try { & (Join-Path $RepoPath 'Backup-BTCT.ps1') -BaseUrl (Get-BaseUrl) -Token $tok } catch { Write-Err $_.Exception.Message }
}

function Invoke-Backups {
    $dir = Get-BackupDir
    if ($script:SessionToken -and (Test-Docker) -and (Test-Running)) {
        Write-Host "Backups (from the server; on this machine in $dir)" -ForegroundColor White
        try {
            $l = Invoke-Api 'admin' 'GET' '/api/backup/list'
            if (-not $l.backups) { Write-Host '  (no backups yet)' }
            foreach ($b in $l.backups) { Write-Host ('  {0,-36} {1,9}  {2}' -f $b.name, (Format-Size $b.bytes), ([DateTime]::Parse($b.createdAt).ToLocalTime().ToString('yyyy-MM-dd HH:mm'))) }
            return
        } catch { Write-Err $_.Exception.Message }
    }
    Write-Host "Backups in $dir (log in from 'Back up now' or 'Scheduled backups' for the server's view)" -ForegroundColor White
    $items = @(Get-ChildItem -LiteralPath $dir -Filter 'btct-backup-*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
    if (-not $items.Count) { Write-Host '  (none yet)'; return }
    foreach ($i in $items) {
        $size = 0; if (-not $i.PSIsContainer) { $size = $i.Length }
        Write-Host ('  {0,-36} {1,9}  {2}' -f $i.Name, (Format-Size $size), $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
    }
}

function Invoke-Schedule([string[]] $a) {
    if (-not (Test-Docker)) { return }
    if (-not (Test-Running)) { Write-Err 'BTCT is not running. Start it with: btct start'; return }
    $mode = ''; $every = ''; $keep = ''; $show = $false
    for ($i = 0; $i -lt $a.Count; $i++) {
        switch ($a[$i]) {
            'on' { $mode = 'on' } 'off' { $mode = 'off' }
            '--every' { $i++; $every = $a[$i] }
            '--keep' { $i++; $keep = $a[$i] }
            '--show' { $show = $true }
            default { Write-Err 'usage: btct schedule [on|off] [--every MIN] [--keep N] [--show]'; return }
        }
    }
    try { $c = Invoke-Api 'admin' 'GET' '/api/backup/config' } catch { Write-Err "could not read the backup settings: $($_.Exception.Message)"; return }
    Write-Row 'schedule' (Format-Schedule $c)
    Write-Row 'folder' "$($c.hostDir) (in the container: $($c.dir))"
    if ($show) { return }
    if (-not ($mode + $every + $keep)) {
        if (-not (Test-Interactive)) { Write-Err 'no console; pass on|off, --every MIN, --keep N'; return }
        $d = 'y/N'; if ($c.enabled) { $d = 'Y/n' }
        $x = Read-Host "Scheduled backups on? [$d]"
        if ($x -match '^(y|yes)$') { $mode = 'on' } elseif ($x -match '^(n|no)$') { $mode = 'off' }
        $every = Read-Host "Interval in minutes [$($c.fullIntervalMin)]"
        $keep = Read-Host "Keep the last N backups, 0 keeps all [$($c.keepLast)]"
    }
    if (-not $mode) { if ($c.enabled) { $mode = 'on' } else { $mode = 'off' } }
    if (-not $every) { $every = "$($c.fullIntervalMin)" }
    if (-not $keep) { $keep = "$($c.keepLast)" }
    if ($every -notmatch '^\d+$' -or [int]$every -lt 1) { Write-Err 'the interval must be a whole number of minutes, at least 1'; return }
    if ($keep -notmatch '^\d+$') { Write-Err 'keep-last must be a whole number (0 keeps all)'; return }
    try {
        $r = Invoke-Api 'admin' 'POST' '/api/backup/config' @{ enabled = ($mode -eq 'on'); fullIntervalMin = [int]$every; keepLast = [int]$keep }
        Write-Row 'schedule' (Format-Schedule $r)
        Write-Ok 'saved'
    } catch { Write-Err "the settings were not saved: $($_.ErrorDetails.Message)$($_.Exception.Message)" }
}

function Invoke-Restore([string[]] $a) {
    if (-not (Test-Docker)) { return }
    $flags = @{}
    if ($a -contains '--keep-browser-caches') { $flags.KeepBrowserCaches = $true }
    if ($a -contains '--partial') { $flags.Partial = $true }
    $name = ($a | Where-Object { $_ -and -not $_.StartsWith('-') } | Select-Object -First 1)
    $dir = Get-BackupDir
    if (-not $name) {
        if (-not (Test-Interactive)) { Write-Err 'no console; pass the backup name'; return }
        $items = @(Get-ChildItem -LiteralPath $dir -Filter 'btct-backup-*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending)
        if (-not $items.Count) { Write-Err "no backups in $dir"; return }
        for ($i = 0; $i -lt $items.Count; $i++) { Write-Host ('  {0,2}) {1}' -f ($i + 1), $items[$i].Name) }
        $pick = Read-Host 'Restore which one (number, Enter cancels)?'
        if ($pick -notmatch '^\d+$' -or [int]$pick -lt 1 -or [int]$pick -gt $items.Count) { Write-Info 'cancelled'; return }
        $name = $items[[int]$pick - 1].Name
    }
    $restore = Join-Path $RepoPath 'Restore-BTCT.ps1'
    Write-Info "verifying $name (BTCT keeps running)"
    try { & $restore -BackupName $name -Verify -HostBackupDir $dir } catch { Write-Err $_.Exception.Message; return }
    Write-Warn 'a restore replaces ALL current data with this backup (the current data is kept in /data/pre-restore-<stamp>/ in the volume)'
    if (-not $script:AssumeYes) {
        $typed = Read-Host "Type the backup name ($name) to restore it"
        if ($typed -ne $name -and "$typed.zip" -ne $name) { Write-Info 'cancelled; nothing changed'; return }
    }
    try { & $restore -BackupName $name -Force -HostBackupDir $dir @flags } catch { Write-Err $_.Exception.Message; return }
    $null = Wait-Healthy
}

function Invoke-Passwords {
    if (-not (Test-Docker)) { return }
    if (-not (Test-Running)) { Write-Err 'BTCT is not running. Start it with: btct start'; return }
    Write-Warn 'this prints account passwords on the screen'
    if ((Test-Interactive) -and -not (Confirm-Step 'Show them?' $false)) { return }
    Invoke-Compose exec -T btct cat /data/initial-passwords.txt
    if ($LASTEXITCODE -ne 0) { Write-Info 'no generated passwords (all set in .env, or the file was deleted)' }
}

function Invoke-Logs([string[]] $a) {
    if (-not (Test-Docker)) { return }
    $lines = 100
    foreach ($x in $a) { if ($x -match '^\d+$') { $lines = [int]$x } }
    if ($a -contains '-f' -or $a -contains '--follow') {
        Write-Info 'following the log; Ctrl+C stops it (and ends this menu; run btct again)'
        Invoke-Compose logs -f "--tail=$lines" btct
    } else { Invoke-Compose logs "--tail=$lines" btct }
}

# ── update and rollback ─────────────────────────────────────────────────
$UpdateBranch = 'comp-ready'      # where `btct update` pulls from unless -Branch says otherwise
$UpdateRemote = 'origin'
$StateFile = Join-Path $RepoPath '.btct-update'   # untracked: built=<commit the running image came from>
$SnapKeep = 3

# A native command with stderr folded into the output. Windows PowerShell 5.1
# turns redirected stderr into errors, which $ErrorActionPreference = 'Stop'
# would throw on, so it is relaxed for the call.
function Invoke-Native([string] $exe, [string[]] $argv) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        $out = @(& $exe @argv 2>&1 | ForEach-Object { "$_" })
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $old }
    return [pscustomobject]@{ Code = $code; Out = ($out -join "`n").Trim() }
}
function Invoke-Git([string[]] $a) {
    $env:GIT_TERMINAL_PROMPT = '0'
    return (Invoke-Native 'git' (@('-C', $RepoPath) + $a))
}

function Get-State([string] $key) {
    if (-not (Test-Path -LiteralPath $StateFile)) { return '' }
    $v = ''
    foreach ($l in [System.IO.File]::ReadAllLines($StateFile, $Utf8NoBom)) { if ($l.StartsWith("$key=")) { $v = $l.Substring($key.Length + 1) } }
    return $v
}
function Set-State([string] $key, [string] $value) {
    $lines = @()
    if (Test-Path -LiteralPath $StateFile) { $lines = @([System.IO.File]::ReadAllLines($StateFile, $Utf8NoBom) | Where-Object { -not $_.StartsWith("$key=") }) }
    try { [System.IO.File]::WriteAllLines($StateFile, [string[]]($lines + "$key=$value"), $Utf8NoBom) } catch { Write-Warn "could not write $StateFile" }
}

# The image compose builds and runs, and the tag the one it replaces keeps.
function Get-ComposeImage {
    $r = Invoke-Native 'docker' @('compose', '--project-directory', $RepoPath, 'config', '--images')
    $img = ''
    if ($r.Code -eq 0 -and $r.Out) { $img = ($r.Out -split "`n")[0].Trim() }
    if (-not $img) { $img = 'btct:latest' }
    return $img
}
function Get-PreviousTag([string] $img) {
    $leaf = $img.Substring($img.LastIndexOf('/') + 1)
    if ($leaf.Contains(':')) { $img = $img.Substring(0, $img.LastIndexOf(':')) }
    return "${img}:previous"
}
function Get-DataVolume {
    $v = (& docker inspect -f '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}' $CName 2>$null | Out-String).Trim()
    if (-not $v) { $v = "$($script:Project)_btct-data" }
    return $v
}
function Test-Image([string] $ref) { $null = & docker image inspect $ref 2>$null; return ($LASTEXITCODE -eq 0) }

# The same shell script as btct.sh, run in a throwaway container of the BTCT
# image (it has tar and gzip, and it is already on this machine).
# No double quotes: Windows PowerShell 5.1 does not escape them in a native
# command's arguments. The names involved never contain spaces.
$SnapshotScript = @'
set -e
tar -czf /out/$1.partial --numeric-owner -C /data .
chown 1000:1000 /out/$1.partial
chmod 600 /out/$1.partial
mv /out/$1.partial /out/$1
ls -1 /out | grep -E '^pre-update-[0-9]{8}-[0-9]{6}[.]tgz$' | sort -r | tail -n +$(($2 + 1)) | while read -r old; do rm -f /out/$old; done
'@
$RestoreScript = @'
set -e
f=/snap/$1
gzip -t $f
tar -tzf $f >/dev/null
aside=/data/pre-rollback-$2
mkdir $aside
chown 1000:1000 $aside
for e in /data/* /data/.[!.]* /data/..?*; do
  [ -e $e ] || continue
  case ${e##*/} in pre-rollback-*) continue ;; esac
  mv $e $aside/
done
tar -xzpf $f --numeric-owner -C /data
'@
function Invoke-Helper([string] $img, [string] $vol, [bool] $volReadOnly, [string] $dir, [string] $target, [bool] $dirReadOnly, [string] $script, [string[]] $scriptArgs) {
    $vro = ''; if ($volReadOnly) { $vro = ',readonly' }
    $dro = ''; if ($dirReadOnly) { $dro = ',readonly' }
    # LF only: the script runs in sh.
    $body = $script -replace "`r", ''
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try {
        & docker run --rm --user 0 --network none --entrypoint sh --mount "type=volume,source=$vol,target=/data$vro" --mount "type=bind,source=$dir,target=$target$dro" $img -c $body sh @scriptArgs | Out-Host
        return ($LASTEXITCODE -eq 0)
    } finally { $ErrorActionPreference = $old }
}

function Show-RollbackHint([string] $prev, [string] $snap) {
    Write-Host ''
    Write-Host '  How to go back' -ForegroundColor White
    Write-Host "    btct rollback            run the image from before this update again ($prev)"
    if ($snap) { Write-Host "    btct rollback --data     the same, and put the data back to $snap" }
    Write-Host '  The data volume was not changed by the update; only the image is new.'
}

function Show-GitAuthHint {
    Write-Host ''
    Write-Host '  The repo is private, so this machine needs a GitHub login once. Either:' -ForegroundColor White
    Write-Host '    a) GitHub CLI:   gh auth login     then     gh auth setup-git'
    Write-Host '    b) a fine-grained token (GitHub > Settings > Developer settings > Fine-grained'
    Write-Host '       tokens; only this repository; Contents: Read-only), then:'
    Write-Host "         git -C `"$RepoPath`" config credential.helper store"
    Write-Host "         git -C `"$RepoPath`" fetch $UpdateRemote"
    Write-Host '       and give your GitHub user name, with the token as the password. (Git for'
    Write-Host '       Windows usually opens its own sign-in window instead, which also works.)'
    Write-Host '  Then: btct update'
}

function Invoke-Update([string[]] $a) {
    $branch = ''; $rebuild = $false
    for ($i = 0; $i -lt $a.Count; $i++) {
        $x = [string]$a[$i]
        if ($x -in '-Branch', '--branch') {
            if ($i + 1 -ge $a.Count) { Write-Err "$x needs a name"; return $false }
            $branch = [string]$a[$i + 1]; $i++
        } elseif ($x -like '--branch=*') { $branch = $x.Substring(9) }
        elseif ($x -in '-Rebuild', '--rebuild') { $rebuild = $true }
        else { Write-Err "unknown option for update: $x (btct update [-Branch NAME] [-Rebuild] [-Yes])"; return $false }
    }
    $target = $UpdateBranch; if ($branch) { $target = $branch }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Err 'git is not installed'; return $false }
    if (-not (Test-Docker)) { return $false }
    if ((Invoke-Git @('rev-parse', '--git-dir')).Code -ne 0) { Write-Err "$RepoPath is not a git checkout"; return $false }
    if ((Invoke-Native 'git' @('check-ref-format', '--branch', $target)).Code -ne 0) { Write-Err "not a branch name: $target"; return $false }
    $remoteUrl = Invoke-Git @('remote', 'get-url', $UpdateRemote)
    if ($remoteUrl.Code -ne 0) { Write-Err "the checkout has no remote named $UpdateRemote"; return $false }

    $dirty = (Invoke-Git @('status', '--porcelain', '--untracked-files=no')).Out
    if ($dirty) {
        Write-Err 'the checkout has local changes to tracked files, so it is not updated:'
        $dirty -split "`n" | ForEach-Object { Write-Host "    $_" }
        Write-Host "  Set them aside and update:   git -C `"$RepoPath`" stash push -m 'before btct update'; btct update"
        Write-Host "  (bring them back later with: git -C `"$RepoPath`" stash pop)"
        Write-Host "  Or throw them away:          git -C `"$RepoPath`" checkout -- ."
        Write-Host '  Settings belong in .env, which git does not track, so they are never in the way.'
        return $false
    }

    $cur = (Invoke-Git @('symbolic-ref', '--quiet', '--short', 'HEAD')).Out
    $use = $target; $doSwitch = $false
    if ($cur -ne $target) {
        if ($cur) { Write-Warn "the checkout is on the branch '$cur', not '$target'" }
        else { Write-Warn "the checkout is not on a branch (detached at $((Invoke-Git @('rev-parse', '--short', 'HEAD')).Out))" }
        if (Confirm-Step "Switch it to '$target' and update from there?" $true) { $doSwitch = $true }
        elseif ($cur) { $use = $cur; Write-Info "staying on '$cur'" }
        else { Write-Err 'a detached checkout cannot be updated; run btct update again and answer yes'; return $false }
    }
    $ref = "$UpdateRemote/$use"

    Write-Info "fetching '$use' from $UpdateRemote ($($remoteUrl.Out))"
    $fo = Invoke-Git @('fetch', '--quiet', $UpdateRemote, "+refs/heads/${use}:refs/remotes/$ref")
    if ($fo.Code -ne 0) {
        if ($fo.Out) { $fo.Out -split "`n" | ForEach-Object { Write-Host "    $_" } }
        if ($fo.Out -match "couldn't find remote ref|could not find remote ref") { Write-Err "$UpdateRemote has no branch '$use'; nothing changed" }
        elseif ($fo.Out -match 'Authentication failed|could not read Username|could not read Password|terminal prompts disabled|Permission denied \(publickey|Repository not found|Invalid username or password|error: 40[13]|returned error: 40[134]') {
            Write-Err 'the fetch was refused: this machine has no GitHub login for the repo; nothing changed'
            Show-GitAuthHint
        } else { Write-Err 'fetch failed (offline, or the remote is unreachable); nothing changed' }
        return $false
    }

    $head = (Invoke-Git @('rev-parse', 'HEAD')).Out
    $before = (Invoke-Git @('log', '-1', '--format=%h %s')).Out
    if ($doSwitch -and (Invoke-Git @('show-ref', '--verify', '--quiet', "refs/heads/$target")).Code -eq 0 -and
        (Invoke-Git @('merge-base', '--is-ancestor', "refs/heads/$target", $ref)).Code -ne 0) {
        Write-Err "the local '$target' has commits that are not on $ref, so it cannot be fast-forwarded; nothing changed"
        return $false
    }
    $n = 0
    if (-not $doSwitch -and (Invoke-Git @('merge-base', '--is-ancestor', 'HEAD', $ref)).Code -ne 0) {
        if ((Invoke-Git @('merge-base', '--is-ancestor', $ref, 'HEAD')).Code -ne 0) {
            Write-Err "'$use' and $ref have both moved on (local commits that are not on the remote); nothing changed"
            return $false
        }
    } else { $n = [int](Invoke-Git @('rev-list', '--count', "HEAD..$ref")).Out }
    $up = ''
    if (-not $doSwitch) {
        $u = Invoke-Git @('rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}')
        if ($u.Code -eq 0) { $up = $u.Out }
        else {
            if ((Invoke-Git @('branch', '--quiet', "--set-upstream-to=$ref", $use)).Code -eq 0) { Write-Info "'$use' had no upstream; it now tracks $ref" }
        }
    }
    $track = ''; if ($up) { $track = ", tracking $up" }
    $curName = $cur; if (-not $curName) { $curName = 'detached' }
    Write-Host "  now:   $before ($curName$track)"
    $built = Get-State 'built'
    $hasC = Test-Exists
    $running = Test-Running
    if (-not $doSwitch -and $n -eq 0) {
        if (-not $rebuild -and $built -eq $head) {
            Write-Ok 'already up to date, and the image BTCT runs was built from this commit'
            if (-not $running) { Write-Host '  BTCT is not running; start it with: btct start' }
            return $true
        }
        Write-Info "no new commits on $ref"
        if (-not $rebuild) {
            Write-Host "  The running image may be older than this checkout (no record that it was built from $($head.Substring(0, 7)))."
            if (-not (Confirm-Step 'Rebuild the image from this checkout and restart BTCT (data is kept and snapshotted first)?' $false)) { Write-Info 'nothing changed'; return $true }
        }
    } else {
        if ($doSwitch) { Write-Host "  switch: $curName -> $target" }
        Write-Host "  $n new commit(s) on ${ref}:"
        (Invoke-Git @('log', '--oneline', "HEAD..$ref")).Out -split "`n" | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" }
        if ($n -gt 20) { Write-Host "    ... and $($n - 20) more" }
        if (-not (Confirm-Step 'Update to them: build the new image (BTCT keeps running), then stop it for a few seconds to snapshot the data, then start the new version?' $false)) { Write-Info 'nothing changed'; return $true }
    }

    # Where the data is, where the snapshot goes, and whether it fits.
    $img = Get-ComposeImage
    $prev = Get-PreviousTag $img
    $snapDir = Get-BackupDir
    $vol = ''; $oldImg = ''; $takeSnap = $false; $snapPath = ''
    if ($hasC) {
        $vol = Get-DataVolume
        $oldImg = (& docker inspect -f '{{.Image}}' $CName 2>$null | Out-String).Trim()
        $takeSnap = $true
        $du = Invoke-Native 'docker' @('run', '--rm', '--user', '0', '--network', 'none', '--entrypoint', 'du', '--mount', "type=volume,source=$vol,target=/data,readonly", $oldImg, '-sk', '/data')
        $needKb = 0; if ($du.Code -eq 0 -and $du.Out -match '^(\d+)') { $needKb = [int64]$Matches[1] }
        $freeKb = -1
        try {
            $p = $snapDir
            while (-not (Test-Path -LiteralPath $p) -and (Split-Path -Parent $p)) { $p = Split-Path -Parent $p }
            $freeKb = [int64](([System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($p)))).AvailableFreeSpace / 1KB)
        } catch { $freeKb = -1 }
        if ($needKb -gt 0 -and $freeKb -ge 0 -and $freeKb -lt ($needKb + 102400)) {
            Write-Warn "not enough free space for a pre-update snapshot: the data is $(Format-Size ($needKb * 1KB)), $snapDir has $(Format-Size ($freeKb * 1KB)) free"
            if (Confirm-Step 'Update without a snapshot (the data volume itself is kept either way)?' $false) { $takeSnap = $false }
            else { Write-Info 'nothing changed; free some space (or move the backup folder: btct backup-dir) and run btct update again'; return $false }
        }
    }

    # 1. the code
    $back = { if ($doSwitch) { $null = Invoke-Git @('checkout', '--quiet', $(if ($cur) { $cur } else { $head })) } else { $null = Invoke-Git @('reset', '--keep', '--quiet', $head) } }
    $gitOk = $true
    if ($doSwitch) {
        if ((Invoke-Git @('show-ref', '--verify', '--quiet', "refs/heads/$target")).Code -eq 0) {
            $r = Invoke-Git @('checkout', '--quiet', $target)
            if ($r.Code -eq 0) { $r = Invoke-Git @('merge', '--ff-only', '--quiet', $ref) }
        } else { $r = Invoke-Git @('checkout', '--quiet', '-b', $target, '--track', $ref) }
        if ($r.Code -ne 0) { $gitOk = $false; Write-Host "    $($r.Out)" }
        else { $null = Invoke-Git @('branch', '--quiet', "--set-upstream-to=$ref", $target) }
    } elseif ($n -gt 0) {
        $r = Invoke-Git @('merge', '--ff-only', '--quiet', $ref)
        if ($r.Code -ne 0) { $gitOk = $false; Write-Host "    $($r.Out)" }
    }
    if (-not $gitOk) {
        if ($doSwitch) { $null = Invoke-Git @('checkout', '--quiet', $(if ($cur) { $cur } else { $head })) }
        Write-Err "git could not move the checkout to $ref; nothing changed"
        return $false
    }
    $after = (Invoke-Git @('log', '-1', '--format=%h %s')).Out
    Write-Host "  before: $before"
    Write-Host "  after:  $after"

    # 2. hold on to the running image: with the containerd image store the
    # image a rebuild takes the tag from is deleted at once, even in use.
    $hold = ''
    if ($oldImg) {
        $hold = $prev.Substring(0, $prev.Length - ':previous'.Length) + ':update-hold'
        if ((Invoke-Native 'docker' @('tag', $oldImg, $hold)).Code -ne 0) { & $back; Write-Err 'could not tag the running image; nothing changed'; return $false }
    }

    # 3. build while the old container keeps serving
    Write-Info 'building the new image while BTCT keeps running (several minutes on a small box)'
    Invoke-Compose build btct | Out-Host
    if ($LASTEXITCODE -ne 0) {
        & $back
        if ($hold) { $null = Invoke-Native 'docker' @('image', 'rm', $hold) }
        Write-Err "the build failed. The checkout is back on $before and BTCT keeps running the old version; nothing else changed."
        return $false
    }
    Write-Ok "built $img"

    # 4. the image that ran until now becomes <image>:previous
    if ($hold) {
        if ($running -and (Test-Healthy)) { $null = Invoke-Native 'docker' @('tag', $hold, $prev); Write-Info "kept the image that ran until now as $prev" }
        elseif (Test-Image $prev) { Write-Warn "BTCT is not healthy right now, so $prev keeps pointing at the last image that was" }
        else { $null = Invoke-Native 'docker' @('tag', $hold, $prev); Write-Info "kept the image that ran until now as $prev" }
    }

    # 5. stop, snapshot, start
    if ($hasC) {
        Write-Info 'stopping BTCT (it flushes its data first)'
        Invoke-Compose stop btct | Out-Host
        if ($LASTEXITCODE -ne 0) { Write-Err 'could not stop the container; BTCT keeps running the old version'; return $false }
        if ($takeSnap) {
            Write-Info "snapshotting the data volume $vol"
            if (-not (Test-Path -LiteralPath $snapDir)) { New-Item -ItemType Directory -Path $snapDir -Force | Out-Null }
            $name = 'pre-update-{0}.tgz' -f (Get-Date -Format 'yyyyMMdd-HHmmss')
            if (Invoke-Helper $hold $vol $true $snapDir '/out' $false $SnapshotScript @($name, "$SnapKeep")) {
                $snapPath = Join-Path $snapDir $name
                Write-Ok "snapshot: $snapPath"
                Set-State 'snapshot' $snapPath
            } else {
                Write-Err 'the snapshot failed'
                if (-not (Confirm-Step 'Start the new version anyway, without a snapshot?' $false)) {
                    Write-Info 'starting the old version again'
                    Invoke-Compose start btct | Out-Host; $script:Port = ''; $null = Wait-Healthy
                    Write-Host '  The new image is built; run btct update again once the snapshot problem is fixed.'
                    return $false
                }
            }
        }
    }
    Set-State 'previous_commit' $head
    Write-Info 'starting the new version'
    $script:Port = ''
    Invoke-Compose up -d | Out-Host
    $upCode = $LASTEXITCODE
    if ($hold) { $null = Invoke-Native 'docker' @('image', 'rm', $hold) }
    if ($upCode -ne 0) { Write-Err 'compose up failed'; Show-RollbackHint $prev $snapPath; return $false }
    if (-not (Wait-Healthy)) { Write-Err 'the new version did not come up healthy'; Show-RollbackHint $prev $snapPath; return $false }
    Set-State 'built' (Invoke-Git @('rev-parse', 'HEAD')).Out
    Write-Ok "updated to $after"
    if ($vol) { Write-Host "  data: kept in the volume $vol" }
    if ($snapPath) { Write-Host "  pre-update snapshot: $snapPath (the newest $SnapKeep are kept)" }
    Write-Host "  open $(Get-BaseUrl)"
    return $true
}

function Invoke-Rollback([string[]] $a) {
    $withData = 0; $snap = ''
    foreach ($x in $a) {
        if ($x -in '--data', '-Data') { $withData = 1 }
        elseif ($x -in '--no-data', '-NoData') { $withData = -1 }
        elseif ($x.StartsWith('-')) { Write-Err "unknown option for rollback: $x (btct rollback [-Data] [SNAPSHOT])"; return $false }
        else { $snap = $x }
    }
    if (-not (Test-Docker)) { return $false }
    $img = Get-ComposeImage
    $prev = Get-PreviousTag $img
    if (-not (Test-Image $prev)) { Write-Err "there is no $prev image to go back to (btct update keeps one each time it runs)"; return $false }
    $dir = Get-BackupDir
    if ($snap) { $snap = Split-Path -Leaf $snap }
    else {
        $s = Get-ChildItem -LiteralPath $dir -Filter 'pre-update-*.tgz' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^pre-update-\d{8}-\d{6}\.tgz$' } | Sort-Object Name | Select-Object -Last 1
        if ($s) { $snap = $s.Name }
    }
    $created = (& docker image inspect -f '{{.Created}}' $prev 2>$null | Out-String).Trim()
    Write-Host "  go back to: $prev (built $($created.Substring(0, [Math]::Min(16, $created.Length)).Replace('T', ' ')))"
    if ($withData -eq 0 -and $snap -and (Test-Interactive) -and -not $script:AssumeYes) {
        Write-Host "  newest data snapshot: $(Join-Path $dir $snap)"
        if (Confirm-Step 'Also put the data back to that snapshot? Everything written since is moved aside, not deleted' $false) { $withData = 1 }
    }
    if ($withData -eq 1) {
        if (-not $snap) { Write-Err "no pre-update-*.tgz snapshot in $dir"; return $false }
        if (-not (Test-Path -LiteralPath (Join-Path $dir $snap))) { Write-Err "no snapshot $snap in $dir"; return $false }
    }
    $q = 'Run the previous version again?'
    if ($withData -eq 1) { $q = "Run the previous version again with the data from $snap?" }
    if (-not (Confirm-Step $q $true)) { Write-Info 'nothing changed'; return $true }

    if ((Invoke-Native 'docker' @('tag', $prev, $img)).Code -ne 0) { Write-Err "could not tag $prev as $img"; return $false }
    Write-Ok "$img now points at the previous image"
    if ($withData -eq 1) {
        $vol = Get-DataVolume
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        Write-Info 'stopping BTCT (it flushes its data first)'
        Invoke-Compose stop btct | Out-Host
        if ($LASTEXITCODE -ne 0) { Write-Err 'could not stop the container'; return $false }
        Write-Info "putting the data back from $snap (the current data goes to /data/pre-rollback-$stamp/ in the volume)"
        if (-not (Invoke-Helper $img $vol $false $dir '/snap' $true $RestoreScript @($snap, $stamp))) {
            Write-Err "putting the data back failed; the data that was there is in /data/pre-rollback-$stamp/ if that folder was made"
            return $false
        }
        Write-Ok "data put back from $snap"
    }
    Write-Info 'starting the previous version'
    $script:Port = ''
    Invoke-Compose up -d --no-build | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Err 'compose up failed'; return $false }
    if (-not (Wait-Healthy)) { return $false }
    Set-State 'built' ''
    Write-Ok 'rolled back. The checkout still has the newer code; the next btct update builds it again.'
    return $true
}

function Invoke-Check {
    # competition-day.sh is the Kali launcher; on Windows check what this box needs.
    if (-not (Test-Docker)) { return }
    Write-Ok "docker: $((& docker version --format '{{.Server.Version}}' 2>$null | Out-String).Trim())"
    Write-Ok "compose: $((& docker compose version --short 2>$null | Out-String).Trim()), project '$($script:Project)' ($($script:ProjectFrom))"
    if (Get-EnvValue 'AUTH_SECRET') { Write-Ok '.env has an AUTH_SECRET' } else { Write-Warn '.env has no AUTH_SECRET (btct start makes one)' }
    $dir = Get-BackupDir
    if (Test-Path -LiteralPath $dir) { Write-Ok "backup folder: $dir ($(Get-FreeText $dir))" } else { Write-Warn "backup folder $dir does not exist yet" }
    if (Test-Running) {
        if (Test-Healthy) { Write-Ok "btct is running and /healthz answers on port $(Get-HostPort)" } else { Write-Warn 'btct is running but /healthz does not answer' }
    } else { Write-Info 'btct is not running (btct start)' }
}

function Get-ProfilePath {
    if ($env:BTCT_PROFILE) { return $env:BTCT_PROFILE }   # tests
    return $PROFILE.CurrentUserCurrentHost
}

function Invoke-Install {
    $prof = Get-ProfilePath
    $line = "function btct { & '$($SelfPath -replace "'", "''")' @args }  $AliasMark"
    $dir = Split-Path -Parent $prof
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $lines = @()
    if (Test-Path -LiteralPath $prof) { $lines = @([System.IO.File]::ReadAllLines($prof, $Utf8NoBom)) }
    $marked = @($lines | Where-Object { $_.EndsWith($AliasMark) })
    if ($marked.Count -eq 1 -and $marked[0] -eq $line) { Write-Ok "$prof already has the btct function" }
    else {
        $kept = @($lines | Where-Object { -not $_.EndsWith($AliasMark) })
        [System.IO.File]::WriteAllLines($prof, [string[]]($kept + $line), $Utf8NoBom)
        Write-Ok "added the btct function to $prof"
    }
    Write-Host ''
    Write-Host 'Use it now:  . $PROFILE   or open a new PowerShell. Then type: btct'
    Write-Host 'If PowerShell refuses to load the profile: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned'
}

function Invoke-Uninstall {
    $prof = Get-ProfilePath
    if ((Test-Path -LiteralPath $prof) -and ([System.IO.File]::ReadAllText($prof, $Utf8NoBom)).Contains($AliasMark)) {
        $kept = @([System.IO.File]::ReadAllLines($prof, $Utf8NoBom) | Where-Object { -not $_.EndsWith($AliasMark) })
        [System.IO.File]::WriteAllLines($prof, [string[]]$kept, $Utf8NoBom)
        Write-Ok "removed the btct function from $prof"
    } else { Write-Info "no btct function in $prof" }
    Write-Host 'Open a new PowerShell (or run: Remove-Item function:btct) to drop it from this one.'
}

function Show-Help {
    $lines = [System.IO.File]::ReadAllLines($SelfPath)
    foreach ($l in $lines | Select-Object -Skip 1) {
        if (-not $l.StartsWith('#')) { break }
        Write-Host ($l -replace '^# ?', '')
    }
}

$MenuItems = [ordered]@{
    '1' = 'Status'; '2' = 'Start'; '3' = 'Stop'; '4' = 'Restart'; '5' = 'Set backup folder'
    '6' = 'Back up now'; '7' = 'List backups'; '8' = 'Scheduled backups'; '9' = 'Restore a backup'
    '10' = 'Show passwords'; '11' = 'Logs'; '12' = 'Update to the latest comp-ready (keeps the data)'
    '13' = 'Roll back the last update'; '14' = 'Check'; '15' = 'Install / uninstall the btct command'; '0' = 'Quit'
}

function Invoke-Choice([string] $c) {
    switch ($c) {
        '1' { Invoke-Status } '2' { Invoke-Start } '3' { Invoke-Stop } '4' { Invoke-Restart }
        '5' { Invoke-BackupDir @() } '6' { Invoke-Backup } '7' { Invoke-Backups } '8' { Invoke-Schedule @() }
        '9' { Invoke-Restore @() } '10' { Invoke-Passwords }
        '11' { $x = Read-Host 'f = follow (Ctrl+C ends the menu), Enter = last 100 lines'; if ($x -eq 'f') { Invoke-Logs @('-f') } else { Invoke-Logs @() } }
        '12' { $null = Invoke-Update @() } '13' { $null = Invoke-Rollback @() } '14' { Invoke-Check }
        '15' { $x = Read-Host 'i = install, u = uninstall'; if ($x -eq 'i') { Invoke-Install } elseif ($x -eq 'u') { Invoke-Uninstall } else { Write-Info 'nothing changed' } }
        default { Write-Err "no such entry: $c" }
    }
}

function Get-MenuHeader {
    $st = 'not running'
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $s = (& docker inspect -f '{{.State.Status}}{{if .State.Health}}, {{.State.Health.Status}}{{end}}' $CName 2>$null | Out-String).Trim()
        if ($LASTEXITCODE -eq 0 -and $s) { $st = $s } elseif ($LASTEXITCODE -ne 0) { $st = 'not created' }
    }
    return "BTCT $st  |  $(Get-BaseUrl)  |  backups: $(Get-BackupDir)"
}

function Show-Menu {
    Find-ProjectQuiet
    while ($true) {
        Write-Host ''
        Write-Host (Get-MenuHeader) -ForegroundColor White
        foreach ($k in $MenuItems.Keys) { Write-Host ('  {0,2}) {1}' -f $k, $MenuItems[$k]) }
        $c = Read-Host 'Choose'
        if ($null -eq $c -or $c -eq '0' -or $c -eq 'q') { return }
        if (-not $c) { continue }
        Write-Host ''
        try { Invoke-Choice $c } catch { Write-Err $_.Exception.Message }
        Write-Host ''
        $null = Read-Host 'Press Enter to return to the menu'
    }
}

# ── Dispatch ────────────────────────────────────────────────────────────
$argv = @($args | Where-Object { $_ -notin '-y', '--yes', '-Yes' })
if ($argv.Count -ne $args.Count) { $script:AssumeYes = $true }
$cmd = 'menu'
if ($argv.Count -gt 0) { $cmd = [string]$argv[0] }
$rest = @()
if ($argv.Count -gt 1) { $rest = @($argv[1..($argv.Count - 1)]) }

switch ($cmd) {
    'menu' { Show-Menu }
    'status' { Invoke-Status }
    'start' { Invoke-Start }
    'stop' { Invoke-Stop }
    'restart' { Invoke-Restart }
    { $_ -in 'backup-dir', 'backup-folder' } { Invoke-BackupDir $rest }
    'backup' { Invoke-Backup }
    { $_ -in 'backups', 'list' } { Invoke-Backups }
    'schedule' { Invoke-Schedule $rest }
    'restore' { Invoke-Restore $rest }
    'passwords' { Invoke-Passwords }
    'logs' { Invoke-Logs $rest }
    'update' { if (Invoke-Update $rest | Select-Object -Last 1) { exit 0 } else { exit 1 } }
    'rollback' { if (Invoke-Rollback $rest | Select-Object -Last 1) { exit 0 } else { exit 1 } }
    'check' { Invoke-Check }
    'install' { Invoke-Install }
    'uninstall' { Invoke-Uninstall }
    { $_ -in 'help', '-h', '--help' } { Show-Help }
    default { Write-Err "unknown command: $cmd"; Show-Help; exit 2 }
}
