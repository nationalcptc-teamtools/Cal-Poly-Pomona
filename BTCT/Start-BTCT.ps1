# Start-BTCT.ps1: one-click launcher for Been There, Conquered That.
#
# What it does, in order:
#   1. cd to the repo this script lives in.
#   2. Make sure Docker Desktop is running (start it and wait if not).
#   3. Make sure .env holds a private AUTH_SECRET (a fresh one replaces a
#      missing one, the example placeholder, or any value ever committed).
#   4. On the first start (.env has no BACKUP_HOST_DIR) or with
#      -ChooseBackupFolder, run Choose-BackupFolder.ps1: a folder picker for
#      where server backups go. Skipped when nobody is there to answer
#      (-NonInteractive, a scheduled task, BTCT_NO_PROMPT=1), so an
#      unattended start never waits on it.
#   5. `docker compose up -d` (idempotent: no-op if already running).
#       Pass -Update to run `btct.ps1 update` first: pull the latest
#       comp-ready (-Branch NAME for another), build the new image while the
#       old container runs, stop it, snapshot the data volume to the backup
#       folder as pre-update-<stamp>.tgz, start it, wait for health. -Yes
#       answers its questions (implied when nobody can answer).
#   6. Poll http://localhost:8080/healthz until the server answers.
#   7. Open the default browser to the app.
#
# Data persistence:
#   The btct-data named Docker volume survives container restarts AND
#   rebuilds. It holds /data/data.sqlite (users) and /data/yjs (notes,
#   pages, graphs, etc.). The ONLY way to wipe it is `docker compose
#   down -v`, which this script never does.

[CmdletBinding()]
param(
    [switch] $Update,                # btct.ps1 update: pull comp-ready, build, snapshot, restart
    [string] $Branch = '',           # with -Update: pull this branch instead of comp-ready
    [switch] $Yes,                   # with -Update: answer yes to its questions
    [int]    $HealthTimeoutSeconds = 60,
    [switch] $NoBrowser,             # skip opening the browser
    [switch] $ChooseBackupFolder     # pick the backup folder again (recreates the container)
)
$ErrorActionPreference = 'Stop'

$RepoPath = Split-Path -Parent $PSCommandPath
Push-Location $RepoPath
try {
    Write-Host "[Start-BTCT] repo: $RepoPath" -ForegroundColor DarkGray

    # ── 1. Docker Desktop ──────────────────────────────────────────────
    function Test-DockerReady {
        try {
            $null = & docker info 2>$null
            return $LASTEXITCODE -eq 0
        } catch { return $false }
    }

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "Docker CLI not found on PATH. Install Docker Desktop for Windows first."
    }

    if (-not (Test-DockerReady)) {
        Write-Host "[Start-BTCT] Docker engine isn't responding; starting Docker Desktop..." -ForegroundColor Yellow
        $dockerExe = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
        if (Test-Path $dockerExe) {
            Start-Process -FilePath $dockerExe | Out-Null
        } else {
            Write-Host "[Start-BTCT] couldn't find Docker Desktop.exe; please start it manually." -ForegroundColor Yellow
        }
        $waited = 0
        while (-not (Test-DockerReady)) {
            if ($waited -ge 120) { throw "Docker engine never came up after 120s." }
            Start-Sleep -Seconds 2
            $waited += 2
            Write-Host "  waiting for Docker engine... ${waited}s" -ForegroundColor DarkGray
        }
        Write-Host "[Start-BTCT] Docker engine ready." -ForegroundColor Green
    }

    # ── 1b. Already running? Notify and exit. ──────────────────────────
    # If the btct container is already up there's nothing to do: show a
    # desktop popup and stop, rather than churning `docker compose up`.
    # (-Update still falls through so an explicit rebuild can proceed.)
    function Test-BtctRunning {
        try {
            $names = & docker ps --filter 'name=^btct$' --filter 'status=running' --format '{{.Names}}' 2>$null
            return ([string]$names).Trim() -eq 'btct'
        } catch { return $false }
    }

    if (-not $Update -and -not $ChooseBackupFolder -and (Test-BtctRunning)) {
        Write-Host "[Start-BTCT] container 'btct' is already running; nothing to start." -ForegroundColor Yellow
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [void][System.Windows.Forms.MessageBox]::Show(
                "The BTCT container on Docker is already started.`n`nIt's available at http://localhost:8080.",
                'Been There, Conquered That',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information)
        } catch {
            # No GUI available (headless / remoting): the console message above suffices.
            Write-Host "[Start-BTCT] (popup unavailable: $($_.Exception.Message))" -ForegroundColor DarkGray
        }
        return
    }

    # ── 2. .env ────────────────────────────────────────────────────────
    # .env must hold a private AUTH_SECRET. Older commits tracked .env, so a
    # value that was ever committed is public and gets replaced, as do a
    # missing file, a missing key and the example placeholder. Values are
    # compared, never printed.
    $envPath = Join-Path $RepoPath '.env'
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    function Get-EnvSecret([string] $line) {
        $v = ($line -replace '^AUTH_SECRET=', '').Trim()
        if ($v.Length -ge 2 -and (($v[0] -eq '"' -and $v[-1] -eq '"') -or ($v[0] -eq "'" -and $v[-1] -eq "'"))) {
            $v = $v.Substring(1, $v.Length - 2)
        }
        return $v
    }
    function Confirm-AuthSecret {
        $lines = @()
        # UTF-8 both ways: BACKUP_HOST_DIR can hold any letter, and Windows
        # PowerShell 5.1's Get-Content and Out-File -Encoding ascii would
        # mangle it.
        if (Test-Path $envPath) { $lines = @([System.IO.File]::ReadAllLines($envPath, $utf8NoBom)) }
        $current = ''
        foreach ($l in $lines) { if ($l -match '^AUTH_SECRET=') { $current = Get-EnvSecret $l } }
        $reason = ''
        if (-not (Test-Path $envPath)) { $reason = 'there is no .env' }
        elseif (-not $current) { $reason = '.env has no AUTH_SECRET' }
        elseif ($current -eq 'replace-me-with-64-random-hex-chars') { $reason = '.env holds the example placeholder' }
        elseif (Get-Command git -ErrorAction SilentlyContinue) {
            $history = @(& git -C $RepoPath log -p --all --format= -- .env 2>$null)
            foreach ($h in $history) {
                if ($h -match '^[-+]AUTH_SECRET=' -and (Get-EnvSecret ($h.Substring(1))) -ceq $current) {
                    $reason = 'the AUTH_SECRET in .env was committed to git, so it is public'
                    break
                }
            }
        }
        if (-not $reason) { return }
        Write-Host "[Start-BTCT] writing a fresh AUTH_SECRET to .env ($reason)." -ForegroundColor Yellow
        if ($current) { Write-Host "[Start-BTCT] everyone signed in with the old secret is logged out." -ForegroundColor Yellow }
        $bytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($bytes)
        $rng.Dispose()
        $secret = -join ($bytes | ForEach-Object { $_.ToString('x2') })
        $kept = @($lines | Where-Object { $_ -notmatch '^AUTH_SECRET=' })
        [System.IO.File]::WriteAllLines($envPath, [string[]]@($kept + "AUTH_SECRET=$secret"), $utf8NoBom)
    }
    Confirm-AuthSecret

    # ── 2b. Backup folder ──────────────────────────────────────────────
    # Ask where server backups go on the first start (no BACKUP_HOST_DIR in
    # .env) or when asked to; the picker writes the answer to .env, so later
    # starts go straight on. Never when nobody can answer it.
    $hasBackupDir = $false
    if (Test-Path $envPath) {
        $hasBackupDir = [bool](@([System.IO.File]::ReadAllLines($envPath, $utf8NoBom)) | Where-Object { $_ -match '^BACKUP_HOST_DIR=\s*\S' })
    }
    $interactive = [Environment]::UserInteractive -and -not ([Environment]::GetCommandLineArgs() -match '^-NonI') -and -not $env:BTCT_NO_PROMPT
    if ($ChooseBackupFolder -or -not $hasBackupDir) {
        $chooser = Join-Path $RepoPath 'Choose-BackupFolder.ps1'
        if (-not $interactive) {
            Write-Host "[Start-BTCT] not asking for a backup folder (no one to answer); backups go to .\backups until you run .\Choose-BackupFolder.ps1" -ForegroundColor DarkGray
        } elseif (-not (Test-Path $chooser)) {
            Write-Host "[Start-BTCT] Choose-BackupFolder.ps1 is missing; backups go to .\backups" -ForegroundColor Yellow
        } else {
            Write-Host "[Start-BTCT] choosing the folder for server backups (run .\Choose-BackupFolder.ps1 or Start-BTCT.ps1 -ChooseBackupFolder to change it later)" -ForegroundColor Cyan
            & $chooser -NoApply
            if ($LASTEXITCODE -ne 0) { Write-Host "[Start-BTCT] backup folder not changed." -ForegroundColor Yellow }
        }
    }

    # ── 3. docker compose ──────────────────────────────────────────────
    if ($Update) {
        # The same update as `btct update` (btct.ps1): pull the latest
        # comp-ready (or -Branch), build while the old container runs, stop,
        # snapshot the data volume to the backup folder, start, wait for health.
        Write-Host "[Start-BTCT] -Update: running btct.ps1 update" -ForegroundColor Cyan
        # A tracked, locally edited .env would block the pull, and the commit
        # that untracks it would delete it: set it aside and put it back.
        $kept = $null
        & git ls-files --error-unmatch .env *> $null
        if ($LASTEXITCODE -eq 0 -and (Test-Path $envPath)) {
            $kept = [System.IO.File]::ReadAllText($envPath, $utf8NoBom)
            & git checkout -- .env
        }
        $btctArgs = @('update')
        if ($Branch) { $btctArgs += @('-Branch', $Branch) }
        if ($Yes -or -not $interactive) { $btctArgs += '-y' }
        & (Join-Path $RepoPath 'btct.ps1') @btctArgs
        $updateExit = $LASTEXITCODE
        if ($null -ne $kept) { [System.IO.File]::WriteAllText($envPath, $kept, $utf8NoBom) }
        if ($updateExit -ne 0) { throw "btct.ps1 update failed (exit $updateExit); see above for how to roll back." }
        Confirm-AuthSecret
        & docker compose up -d
    } else {
        & docker compose up -d
    }
    if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (exit $LASTEXITCODE)." }

    # ── 4. wait for healthz ────────────────────────────────────────────
    Write-Host "[Start-BTCT] waiting for http://localhost:8080/healthz ..." -ForegroundColor Cyan
    $healthy = $false
    for ($i = 0; $i -lt $HealthTimeoutSeconds; $i++) {
        try {
            $r = Invoke-WebRequest -Uri 'http://localhost:8080/healthz' `
                                   -UseBasicParsing -TimeoutSec 2
            if ($r.StatusCode -eq 200) { $healthy = $true; break }
        } catch { }
        Start-Sleep -Seconds 1
    }
    if (-not $healthy) {
        Write-Host "[Start-BTCT] healthz didn't respond in ${HealthTimeoutSeconds}s. Recent logs:" -ForegroundColor Red
        & docker compose logs --tail=50
        throw "Server didn't become healthy in time."
    }
    Write-Host "[Start-BTCT] healthy. App is at http://localhost:8080" -ForegroundColor Green
    $backupDir = @([System.IO.File]::ReadAllLines($envPath, $utf8NoBom)) | Where-Object { $_ -match '^BACKUP_HOST_DIR=' } | Select-Object -Last 1
    if ($backupDir) { $backupDir = ($backupDir -replace '^BACKUP_HOST_DIR=', '').Trim().Trim("'").Trim('"') }
    if (-not $backupDir) { $backupDir = Join-Path $RepoPath 'backups' }
    Write-Host "[Start-BTCT] server backups (Admin panel -> Backups) are written to $backupDir" -ForegroundColor DarkGray

    # The server creates Roberto, Warren, Ryan, Anthony, Jesse and Darren
    # (all admins) when they are missing. A password not set in .env is
    # generated and kept in /data/initial-passwords.txt; say where to look.
    & docker compose exec -T btct test -s /data/initial-passwords.txt 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[Start-BTCT] generated passwords for the default accounts: docker compose exec btct cat /data/initial-passwords.txt" -ForegroundColor Yellow
        Write-Host "[Start-BTCT]   (also in 'docker compose logs btct', lines with 'generated password'). Change them after the first login, then delete that file." -ForegroundColor Yellow
    }

    # ── 5. open browser ────────────────────────────────────────────────
    if (-not $NoBrowser) {
        Start-Process 'http://localhost:8080'
    }
}
finally {
    Pop-Location
}
