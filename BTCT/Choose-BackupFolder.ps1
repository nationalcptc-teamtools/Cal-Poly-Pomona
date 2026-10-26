# Choose-BackupFolder.ps1: pick the host folder BTCT writes its backups to.
#
# Scheduled server backups (one btct-backup-YYYYMMDD-HHMMSS.zip per run) are
# written to /backups in the container, which docker-compose.yml bind-mounts
# from BACKUP_HOST_DIR in .env (.\backups next to docker-compose.yml when
# unset). This script sets that value:
#
#   1. Opens the Windows folder picker (System.Windows.Forms
#      FolderBrowserDialog, run on an STA thread; Shell.Application
#      BrowseForFolder if that fails). With no desktop (a remote session
#      without one, -NonInteractive) it asks for a typed path instead, with
#      the current folder as the default.
#   2. Checks the choice: a full path on a drive letter (C:\...), not a
#      network share, a drive root or a system folder. It creates the folder
#      when missing and checks it can write a file there.
#   3. Warns when the drive has less than 3 GB free (12 kept runs of a
#      500-screenshot engagement are about 2.3 GB).
#   4. Writes BACKUP_HOST_DIR to .env in the form Docker Desktop's compose
#      accepts (C:/btct/backups, forward slashes), leaving every other line
#      as it was, then offers to run `docker compose up -d`.
#
# Start-BTCT.ps1 calls it on the first start (when .env has no
# BACKUP_HOST_DIR) and with -ChooseBackupFolder. Run it on its own any time:
#
#   .\Choose-BackupFolder.ps1                       # picker, or typed prompt
#   .\Choose-BackupFolder.ps1 -Path D:\btct-backups # no picker, use this folder
#   .\Choose-BackupFolder.ps1 -NoDialog             # typed prompt only
#   .\Choose-BackupFolder.ps1 -Apply                # run `docker compose up -d` after
#
# Exit codes: 0 saved (or kept), 1 the folder could not be used.

[CmdletBinding()]
param(
    [string] $Path = '',
    [switch] $NoDialog,
    [switch] $Apply,
    [switch] $NoApply,                 # leave the container alone (Start-BTCT.ps1 starts it)
    [string] $EnvFile = ''
)
$ErrorActionPreference = 'Stop'

$RepoPath = Split-Path -Parent $PSCommandPath
if (-not $EnvFile) { $EnvFile = Join-Path $RepoPath '.env' }
$Title = 'BTCT: choose the folder for server backups'
$MinFreeBytes = 3GB
# $IsWindows does not exist in Windows PowerShell 5.1, which only runs on Windows.
$OnWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or [bool](Get-Variable -Name IsWindows -ValueOnly -ErrorAction SilentlyContinue)

function Write-Info([string] $m) { Write-Host "[backup-folder] $m" -ForegroundColor Cyan }
function Write-Warn([string] $m) { Write-Host "[backup-folder] $m" -ForegroundColor Yellow }
function Write-Fail([string] $m) { Write-Host "[backup-folder] $m" -ForegroundColor Red }

# --- .env ---
# Read and written as UTF-8 without a BOM: a folder name can hold any letter,
# and docker compose reads .env as UTF-8.
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

function Get-EnvValue([string] $file, [string] $key) {
    # The last KEY= line wins, as in docker compose; CR and one pair of
    # surrounding quotes are stripped.
    if (-not (Test-Path -LiteralPath $file)) { return '' }
    $value = ''
    foreach ($l in [System.IO.File]::ReadAllLines($file, $Utf8NoBom)) {
        if ($l.StartsWith("$key=")) { $value = $l.Substring($key.Length + 1).TrimEnd("`r").Trim() }
    }
    if ($value.Length -ge 2 -and (($value[0] -eq '"' -and $value[-1] -eq '"') -or ($value[0] -eq "'" -and $value[-1] -eq "'"))) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    return $value
}

function Set-EnvValue([string] $file, [string] $key, [string] $value) {
    # Replace the first KEY= line in place and drop later ones; every other
    # line is kept byte for byte, line endings included.
    $line = "$key=$value"
    $text = ''
    if (Test-Path -LiteralPath $file) { $text = [System.IO.File]::ReadAllText($file, $Utf8NoBom) }
    $nl = "`n"
    if ($text.Contains("`r`n")) { $nl = "`r`n" }
    $pieces = [regex]::Split($text, '(?<=\n)') | Where-Object { $_ -ne '' }
    $out = New-Object System.Text.StringBuilder
    $done = $false
    foreach ($p in $pieces) {
        if ($p.StartsWith("$key=")) {
            if (-not $done) {
                $end = ''
                if ($p.EndsWith("`r`n")) { $end = "`r`n" } elseif ($p.EndsWith("`n")) { $end = "`n" } else { $end = $nl }
                [void]$out.Append($line + $end)
                $done = $true
            }
            continue
        }
        [void]$out.Append($p)
    }
    if (-not $done) {
        if ($out.Length -gt 0 -and -not $out.ToString().EndsWith("`n")) { [void]$out.Append($nl) }
        [void]$out.Append($line + $nl)
    }
    $tmp = "$file.new"
    [System.IO.File]::WriteAllText($tmp, $out.ToString(), $Utf8NoBom)
    if (-not $OnWindows) { & chmod 600 $tmp }
    Move-Item -LiteralPath $tmp -Destination $file -Force
}

# --- Paths ---
# Returns @{ Ok; Path (native); Compose (the .env form); Error }. Pure: it
# touches no disk, so it is testable on any platform with -OnWindows.
function Test-BackupPath([string] $choice, [bool] $onWindows, [string] $userProfile) {
    $p = $choice.Trim().Trim('"')
    if ($p -match "[`r`n'""``$]") {
        return @{ Ok = $false; Error = "the path holds a quote, `$, backtick or line break, which .env and docker compose cannot carry; pick another folder" }
    }
    if ($onWindows) {
        if ($p -match '^(\\\\|//)') { return @{ Ok = $false; Error = "$p is a network share; Docker Desktop cannot mount it reliably. Pick a folder on a local drive (C:\btct\backups)" } }
        if ($p -notmatch '^[A-Za-z]:[\\/]') { return @{ Ok = $false; Error = "'$p' is not a full path; it must start with a drive letter, e.g. C:\btct\backups" } }
        $p = $p -replace '/', '\'
        $p = $p -replace '\\{2,}', '\'
        if ($p.Length -gt 3) { $p = $p.TrimEnd('\') }
        $p = $p.Substring(0, 1).ToUpperInvariant() + $p.Substring(1)
        $low = $p.ToLowerInvariant()
        if ($p.Length -le 3) { return @{ Ok = $false; Error = "$p is a whole drive; pick (or create) a folder on it, e.g. ${p}btct-backups" } }
        $system = @('c:\windows', 'c:\program files', 'c:\program files (x86)', 'c:\programdata', 'c:\users', 'c:\users\public')
        foreach ($s in $system) {
            if ($low -eq $s -or ($s -ne 'c:\users' -and $s -ne 'c:\users\public' -and $low.StartsWith("$s\"))) {
                return @{ Ok = $false; Error = "$p is a system folder; pick (or create) a folder of its own, e.g. C:\btct\backups" }
            }
        }
        if ($userProfile -and $low -eq $userProfile.TrimEnd('\').ToLowerInvariant()) {
            return @{ Ok = $false; Error = "$p is your profile folder; pick (or create) a folder of its own, e.g. $p\btct-backups" }
        }
        $compose = $p -replace '\\', '/'
    } else {
        if ($p -notmatch '^/') { return @{ Ok = $false; Error = "'$p' is not an absolute path (it must start with /)" } }
        if ($p.Contains(':')) { return @{ Ok = $false; Error = "the path holds a ':', which a docker bind mount cannot carry" } }
        if ($p.Length -gt 1) { $p = $p.TrimEnd('/') }
        if ($p -match '^/(bin|boot|dev|etc|home|lib|lib64|media|mnt|opt|proc|root|run|sbin|srv|sys|tmp|usr|var)?$' -or $p -match '^/(usr|etc|proc|sys|dev|boot|run)/') {
            return @{ Ok = $false; Error = "$p is a system folder; pick (or create) a folder of its own" }
        }
        $compose = $p
    }
    # Single quotes keep compose from expanding anything; plain paths stay bare.
    if ($compose -match '[^A-Za-z0-9_./:+-]') { $compose = "'$compose'" }
    return @{ Ok = $true; Path = $p; Compose = $compose; Error = '' }
}

# Create the folder when missing and prove a file can be written there.
function Initialize-BackupFolder([string] $p) {
    if (Test-Path -LiteralPath $p -PathType Leaf) { return "$p exists and is not a folder" }
    if (-not (Test-Path -LiteralPath $p)) {
        try { $null = New-Item -ItemType Directory -Path $p -Force; Write-Info "created $p" }
        catch { return "could not create ${p}: $($_.Exception.Message)" }
    }
    $probe = Join-Path $p (".btct-write-test-" + [guid]::NewGuid().ToString('N'))
    try { [System.IO.File]::WriteAllText($probe, 'ok'); Remove-Item -LiteralPath $probe -Force }
    catch { return "cannot write to ${p}: $($_.Exception.Message)" }
    return ''
}

function Get-FreeBytes([string] $p) {
    try {
        $root = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($p))
        return ([System.IO.DriveInfo]::new($root)).AvailableFreeSpace
    } catch { return $null }
}

# --- Dialogs ---
# Each returns the chosen folder, '' when the person closed it without one,
# or $null when it could not be shown.
function Test-GuiAvailable {
    if (-not $OnWindows) { return $false }
    if (-not [Environment]::UserInteractive) { return $false }
    if ([Environment]::GetCommandLineArgs() -match '^-NonI') { return $false }
    if ($env:SSH_CONNECTION -or $env:SSH_CLIENT) { return $false }   # OpenSSH session: no desktop to draw on
    return $true
}

function Test-CanPrompt {
    if ([Environment]::GetCommandLineArgs() -match '^-NonI') { return $false }
    if ($env:BTCT_NO_PROMPT) { return $false }
    return [Environment]::UserInteractive
}

$FolderDialogScript = {
    param([string] $start, [string] $title)
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()
    # An unshown topmost owner keeps the dialog in front of the console.
    $owner = New-Object System.Windows.Forms.Form -Property @{ TopMost = $true }
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    try {
        $dlg.Description = $title
        $dlg.ShowNewFolderButton = $true
        # .NET 5+ (pwsh 7) shows the Explorer-style picker and can title it.
        if ($dlg.PSObject.Properties['UseDescriptionForTitle']) { $dlg.UseDescriptionForTitle = $true }
        if ($start -and (Test-Path -LiteralPath $start)) { $dlg.SelectedPath = $start }
        if ($dlg.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.SelectedPath }
        return ''
    } finally {
        $dlg.Dispose()
        $owner.Dispose()
    }
}

function Show-WinFormsFolderDialog([string] $start) {
    try {
        # WinForms dialogs need a single-threaded apartment. Windows
        # PowerShell 5.1 and pwsh 7 consoles are STA already; anything else
        # (a host started -MTA) gets a runspace of its own on an STA thread.
        if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA') {
            return [string](& $FolderDialogScript $start $Title)
        }
        $rs = [runspacefactory]::CreateRunspace()
        $rs.ApartmentState = 'STA'
        $rs.ThreadOptions = 'ReuseThread'
        $rs.Open()
        $ps = [powershell]::Create()
        try {
            $ps.Runspace = $rs
            [void]$ps.AddScript($FolderDialogScript.ToString()).AddArgument($start).AddArgument($Title)
            $r = $ps.Invoke()
            if ($ps.HadErrors) { throw $ps.Streams.Error[0].Exception }
            return [string]($r | Select-Object -Last 1)
        } finally { $ps.Dispose(); $rs.Dispose() }
    } catch {
        Write-Warn "the Windows Forms folder picker failed ($($_.Exception.Message)); trying the shell one"
        return $null
    }
}

function Show-ShellFolderDialog {
    try {
        $shell = New-Object -ComObject Shell.Application
        # 0x51: file-system folders only, an edit box, the new-style dialog
        # (with a "Make New Folder" button).
        $f = $shell.BrowseForFolder(0, $Title, 0x51, 0)
        if ($null -eq $f) { return '' }
        return [string]$f.Self.Path
    } catch {
        Write-Warn "the shell folder picker failed too ($($_.Exception.Message))"
        return $null
    }
}

# --- Main ---
function Invoke-ChooseBackupFolder {
    $current = Get-EnvValue $EnvFile 'BACKUP_HOST_DIR'
    if (-not $current) {
        $default = Join-Path $RepoPath 'backups'
    } elseif ($current -match '^(\.[\\/]|[^\\/:]+$|\.\.)') {
        # Relative: compose resolves it next to docker-compose.yml.
        $default = Join-Path $RepoPath ($current -replace '^\.[\\/]', '')
    } else {
        $default = $current
    }
    if ($OnWindows) { $default = $default -replace '/', '\' }

    $result = $null
    for ($try = 1; $try -le 3; $try++) {
        $choice = ''
        if ($Path) {
            $choice = $Path
        } else {
            if (-not $NoDialog) {
                if (Test-GuiAvailable) {
                    Write-Info 'opening the folder picker'
                    $picked = Show-WinFormsFolderDialog $default
                    if ($null -eq $picked) { $picked = Show-ShellFolderDialog }
                    if ($picked) { $choice = $picked }
                    elseif ($null -ne $picked) { Write-Info 'the picker closed without a folder' }
                } else {
                    Write-Info 'no desktop to show a folder picker on, so asking here'
                }
            }
            if (-not $choice) {
                if (Test-CanPrompt) { $choice = Read-Host "Backup folder [$default]" }
                else { Write-Info "no console to ask on; keeping $default" }
            }
        }
        if (-not $choice) { $choice = $default }
        $profileDir = $env:USERPROFILE
        if (-not $OnWindows) { $profileDir = $env:HOME }
        $check = Test-BackupPath $choice $OnWindows $profileDir
        if ($check.Ok) {
            $err = Initialize-BackupFolder $check.Path
            if (-not $err) { $result = $check; break }
            $check.Error = $err
        }
        Write-Fail $check.Error
        if ($Path -or -not (Test-CanPrompt) -or $try -ge 3) {
            Write-Fail 'BACKUP_HOST_DIR left unchanged'
            return 1
        }
        Write-Info "try again (Enter keeps $default)"
    }

    $free = Get-FreeBytes $result.Path
    if ($null -ne $free) {
        $gb = [math]::Round($free / 1GB, 1)
        if ($free -lt $MinFreeBytes) {
            Write-Warn "only $gb GB free on that drive. Each backup is a full copy (about 192 MB for 500 screenshots) and 12 are kept, about 2.3 GB; lower 'keep last' in Admin panel -> Backups or pick a bigger drive"
        } else {
            Write-Info "$gb GB free on that drive"
        }
    }

    $currentCheck = $null
    if ($current) { $currentCheck = Test-BackupPath $current $OnWindows '' }
    if ($currentCheck -and $currentCheck.Ok -and $currentCheck.Compose -eq $result.Compose) {
        Write-Info "BACKUP_HOST_DIR is already $($result.Compose); .env unchanged"
        $changed = $false
    } else {
        Set-EnvValue $EnvFile 'BACKUP_HOST_DIR' $result.Compose
        Write-Info "saved BACKUP_HOST_DIR=$($result.Compose) in $EnvFile"
        $changed = $true
    }

    if ($NoApply) { return 0 }
    $doApply = [bool]$Apply
    if (-not $doApply -and $changed -and (Test-CanPrompt)) {
        $ans = Read-Host "Run 'docker compose up -d' now so the container uses it? [y/N]"
        $doApply = $ans -match '^(y|yes)$'
    }
    if ($doApply) {
        Push-Location $RepoPath
        try {
            & docker compose up -d | Out-Host
            if ($LASTEXITCODE -ne 0) { Write-Fail "docker compose up -d failed (exit $LASTEXITCODE)"; return 1 }
        } finally { Pop-Location }
        Write-Info "done: new backups land in $($result.Path)"
    } elseif ($changed) {
        Write-Info "run 'docker compose up -d' in $RepoPath (or .\Start-BTCT.ps1) to apply it; data in the btct-data volume is kept"
    }
    return 0
}

# Dot-sourcing (`. .\Choose-BackupFolder.ps1`) loads the functions only.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-ChooseBackupFolder)
}
