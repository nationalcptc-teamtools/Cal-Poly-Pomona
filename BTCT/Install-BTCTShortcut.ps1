# Install-BTCTShortcut.ps1: drops a "Been There, Conquered That" shortcut
# on the user's Desktop that runs Start-BTCT.ps1.
#
# Re-run any time the script location or arguments change; the shortcut
# is recreated in place. Pass -Update to make the shortcut launch with
# the -Update flag (runs btct.ps1 update on every click; it asks before it
# changes anything).

[CmdletBinding()]
param(
    [switch] $Update,
    [string] $ShortcutName = 'Been There, Conquered That.lnk'
)
$ErrorActionPreference = 'Stop'

$RepoPath   = Split-Path -Parent $PSCommandPath
$Launcher   = Join-Path $RepoPath 'Start-BTCT.ps1'
if (-not (Test-Path $Launcher)) {
    throw "Couldn't find Start-BTCT.ps1 next to this installer at $Launcher."
}

$DesktopDir = [Environment]::GetFolderPath('Desktop')
$LinkPath   = Join-Path $DesktopDir $ShortcutName

# Use the OS-bundled Windows PowerShell so the shortcut works on any
# Windows 10/11 box without requiring PowerShell 7.
$PsExe = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'

$args = "-NoLogo -ExecutionPolicy Bypass -File `"$Launcher`""
if ($Update) { $args += ' -Update' }

$shell = New-Object -ComObject WScript.Shell
$sc = $shell.CreateShortcut($LinkPath)
$sc.TargetPath       = $PsExe
$sc.Arguments        = $args
$sc.WorkingDirectory = $RepoPath
$sc.WindowStyle      = 1            # 1 = normal; 7 = minimized
$sc.Description      = 'Launch Been There, Conquered That (BTCT)'

# Use the app logo as the shortcut icon. .lnk wants an .ico, so we extract
# one from the PNG using System.Drawing on first install.
$iconSource = Join-Path $RepoPath 'public\new-logo.png'
$iconCache  = Join-Path $RepoPath 'public\new-logo.ico'
if ((Test-Path $iconSource) -and -not (Test-Path $iconCache)) {
    try {
        Add-Type -AssemblyName System.Drawing
        $bmp = [System.Drawing.Bitmap]::FromFile($iconSource)
        $hIcon = $bmp.GetHicon()
        $icon = [System.Drawing.Icon]::FromHandle($hIcon)
        $fs = [System.IO.File]::OpenWrite($iconCache)
        $icon.Save($fs)
        $fs.Close()
        $bmp.Dispose()
    } catch {
        Write-Host "[Install-BTCTShortcut] couldn't build .ico from new-logo.png ($_); using default icon." -ForegroundColor Yellow
    }
}
if (Test-Path $iconCache) {
    $sc.IconLocation = "$iconCache,0"
}

$sc.Save()
Write-Host "[Install-BTCTShortcut] created shortcut: $LinkPath" -ForegroundColor Green
Write-Host "  target: $PsExe $args" -ForegroundColor DarkGray
