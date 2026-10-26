# Restore-BTCT.ps1: restore a backup written by the app into the live volume.
#
# Stops the container, runs the restore CLI inside the image (it verifies the
# ZIP against its manifest, unpacks it into /data/.restore-unpack, builds the
# new data in /data/.restore-staging, keeps the old data in
# /data/pre-restore-<stamp>/, then swaps the SQLite file, the Yjs rooms, the
# assets and the history twins in), and starts the container again.
#
#   .\Restore-BTCT.ps1 btct-backup-20261012-101500.zip
#   .\Restore-BTCT.ps1 btct-backup-20261012-101500.zip -Verify   # check only, server keeps running
#
# The name may be given without .zip. A folder run written before 2026-10-12
# (btct-backup-YYYYMMDD-HHMMSS without .zip) restores the same way.
#
# -Force skips the confirmation prompt. -Partial restores a backup that left a
# category out (see Admin panel -> Backups checkboxes) on top of the existing
# data. -KeepBrowserCaches is for recovery onto a new box: browsers keep their
# cached copies and refill whatever changed after the backup. Without it (a
# rollback) every browser drops its cache, so post-backup edits do not return.
# -HostBackupDir is the host folder mounted at /backups. By default it is
# BACKUP_HOST_DIR from .env (set by Choose-BackupFolder.ps1), else .\backups.

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $BackupName,   # a .zip (or an older folder) under the host backup folder
    [switch] $Force,
    [switch] $Partial,
    [switch] $KeepBrowserCaches,
    [switch] $Verify,
    [string] $HostBackupDir = ''
)
$ErrorActionPreference = 'Stop'

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI not found on PATH."
}

$RepoPath = Split-Path -Parent $PSCommandPath
if (-not $HostBackupDir) {
    # The folder docker-compose.yml mounts: BACKUP_HOST_DIR from .env (the
    # last line wins, quotes stripped, as compose reads it), else .\backups.
    $envPath = Join-Path $RepoPath '.env'
    if (Test-Path -LiteralPath $envPath) {
        foreach ($l in [System.IO.File]::ReadAllLines($envPath, (New-Object System.Text.UTF8Encoding $false))) {
            if ($l -match '^BACKUP_HOST_DIR=(.*)$') { $HostBackupDir = $Matches[1].Trim().Trim("'").Trim('"') }
        }
    }
    if (-not $HostBackupDir) { $HostBackupDir = 'backups' }
    if (-not [System.IO.Path]::IsPathRooted($HostBackupDir)) { $HostBackupDir = Join-Path $RepoPath ($HostBackupDir -replace '^\.[\\/]', '') }
}
$leaf = Split-Path -Leaf $BackupName
if (-not (Test-Path -LiteralPath (Join-Path $HostBackupDir $leaf)) -and (Test-Path -LiteralPath (Join-Path $HostBackupDir "$leaf.zip") -PathType Leaf)) {
    $leaf = "$leaf.zip"
}
if (-not (Test-Path -LiteralPath (Join-Path $HostBackupDir $leaf))) {
    throw "No backup $leaf under $HostBackupDir. Backups are the btct-backup-YYYYMMDD-HHMMSS.zip files there (or folders of that name from older builds); pass -HostBackupDir if compose mounts another folder at /backups."
}

# The image's working directory is /app/server, so the script is restore.mjs.
Push-Location $RepoPath
try {
    if ($Verify) {
        & docker compose run --rm --no-deps btct bun restore.mjs --verify "/backups/$leaf"
        if ($LASTEXITCODE -eq 5) { throw "could not read $leaf inside the container, so it was not checked (exit 5). Make it readable by uid 1000 (chown 1000:1000, or chmod a+r on it and its folder) and run again." }
        if ($LASTEXITCODE -ne 0) { throw "verification failed (exit $LASTEXITCODE)." }
        Write-Host "[Restore-BTCT] $leaf verified." -ForegroundColor Green
        return
    }

    if (-not $Force) {
        Write-Host "About to RESTORE $leaf into the live data volume." -ForegroundColor Yellow
        Write-Host "The current data is kept in /data/pre-restore-<stamp>/ inside the volume." -ForegroundColor Yellow
        $resp = Read-Host "Type 'restore' to continue"
        if ($resp -ne 'restore') {
            Write-Host "[Restore-BTCT] cancelled." -ForegroundColor Red
            return
        }
    }

    Write-Host "[Restore-BTCT] stopping the container..." -ForegroundColor Cyan
    & docker compose stop btct
    if ($LASTEXITCODE -ne 0) { throw "docker compose stop failed." }

    $dockerArgs = @('compose', 'run', '--rm', 'btct', 'bun', 'restore.mjs', "/backups/$leaf", '--yes')
    if ($Partial) { $dockerArgs += '--partial' }
    if ($KeepBrowserCaches) { $dockerArgs += '--keep-browser-caches' }
    Write-Host "[Restore-BTCT] restoring $leaf ..." -ForegroundColor Cyan
    & docker @dockerArgs
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        # 2 (refused), 3 (data still locked), 4 (not enough space) and 5 (the
        # copy could not be read, so it was not checked) change nothing, so
        # the old data comes back up. Anything else leaves the container
        # stopped.
        if ($code -eq 5) {
            & docker compose start btct | Out-Null
            throw "could not read $leaf inside the container, so it was not checked (exit 5); nothing was changed and the container was started again. Make it readable by uid 1000 (chown 1000:1000, or chmod a+r on it and its folder) and run again."
        }
        if ($code -eq 2 -or $code -eq 3 -or $code -eq 4) {
            & docker compose start btct | Out-Null
            throw "restore refused (exit $code); nothing was changed and the container was started again. Check the output above."
        }
        throw "restore failed (exit $code); the container is still stopped. Check the output above, then 'docker compose start btct'."
    }

    Write-Host "[Restore-BTCT] starting the container..." -ForegroundColor Cyan
    & docker compose start btct
    if ($LASTEXITCODE -ne 0) { throw "docker compose start failed." }

    Write-Host "[Restore-BTCT] done. App is reachable at http://127.0.0.1:8080" -ForegroundColor Green
}
finally {
    Pop-Location
}
