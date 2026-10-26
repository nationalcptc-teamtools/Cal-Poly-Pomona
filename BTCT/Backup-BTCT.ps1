# Backup-BTCT.ps1: trigger a BTCT backup through the app's own engine.
#
# The app writes consistent snapshots itself (Admin panel -> Backups), one
# self-contained btct-backup-YYYYMMDD-HHMMSS.zip per run into the host folder
# bind-mounted at /backups (BACKUP_HOST_DIR in .env, set by
# Choose-BackupFolder.ps1; .\backups next to docker-compose.yml when unset).
# Copy that one file anywhere (OneDrive, a USB stick) to keep it off the box. This script only calls the "run now"
# endpoint, so it can be scheduled from Windows Task Scheduler (run the task as
# your own user: Docker Desktop needs a logged-in session).
#
# Token: Admin panel -> Backups -> Reveal. Pass -Token or set BTCT_BACKUP_TOKEN.

[CmdletBinding()]
param(
    [string] $BaseUrl = 'http://127.0.0.1:8080',   # 127.0.0.1, not localhost (see README "Running on Windows")
    [string] $Token   = $env:BTCT_BACKUP_TOKEN
)
$ErrorActionPreference = 'Stop'

if (-not $Token) {
    throw "No token. Pass -Token or set BTCT_BACKUP_TOKEN (Admin panel -> Backups -> Reveal)."
}

$headers = @{ Authorization = "Bearer $Token" }
Write-Host "[Backup-BTCT] requesting a backup from $BaseUrl ..." -ForegroundColor Cyan
try {
    $r = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/backup/run" -Headers $headers -TimeoutSec 3600
} catch {
    $status = $_.Exception.Response.StatusCode.value__
    if ($status -eq 409) {
        Write-Host "[Backup-BTCT] a backup is already running" -ForegroundColor Yellow
        return
    }
    throw "Backup request failed: $($_.Exception.Message) $($_.ErrorDetails.Message)"
}

if ($r.ran) {
    $mb = [math]::Round($r.bytes / 1MB, 1)
    $secs = [math]::Round($r.durationMs / 1000)
    # Where it landed on this machine: BACKUP_HOST_DIR from .env, else .\backups.
    $hostDir = ''
    $envPath = Join-Path (Split-Path -Parent $PSCommandPath) '.env'
    if (Test-Path -LiteralPath $envPath) {
        foreach ($l in [System.IO.File]::ReadAllLines($envPath, (New-Object System.Text.UTF8Encoding $false))) {
            if ($l -match '^BACKUP_HOST_DIR=(.*)$') { $hostDir = $Matches[1].Trim().Trim("'").Trim('"') }
        }
    }
    if (-not $hostDir) { $hostDir = '.\backups' }
    Write-Host "[Backup-BTCT] wrote $($r.name) ($mb MB, $($r.files) files, $secs s) into $hostDir" -ForegroundColor Green
    if ($r.failedRooms -and $r.failedRooms.Count -gt 0) {
        Write-Warning "[Backup-BTCT] $($r.failedRooms.Count) room(s) could not be read and are missing from this backup: $($r.failedRooms -join ', ')"
        exit 1
    }
} else {
    Write-Host "[Backup-BTCT] a backup is already running" -ForegroundColor Yellow
}
