# One fix-and-measure iteration: convert a typst PDF to Word, print it through Word, measure it.
#   .\check_word.ps1 -Pdf <typst.pdf> -Out <dir> -Name <key> [-Fonts <dir>[,<dir>]]
# Needs the pdf2docx venv (see CLAUDE.md), Word, and typst's default fonts in dist\fonts.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Pdf,
  [Parameter(Mandatory = $true)][string]$Out,
  [Parameter(Mandatory = $true)][string]$Name,
  [string[]]$Fonts = @()
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $here "..\..\..")
$py = Join-Path $root ".venv-pdf2docx\Scripts\python.exe"
New-Item -ItemType Directory -Force $Out | Out-Null
$fontArgs = @("--fonts=$(Join-Path $root 'dist\fonts')", "--fonts=$(Join-Path $here 'corpus\fonts')") + ($Fonts | ForEach-Object { "--fonts=$_" })
$docx = Join-Path $Out "$Name.docx"
$json = Join-Path $Out "$Name.json"
& $py -I -B (Join-Path $here "convert.py") --line-breaks=pdf @fontArgs $Pdf $docx $json
if ($LASTEXITCODE -ne 0) { throw "convert.py failed: see $json" }
& powershell -NoProfile -File (Join-Path $here "render_word.ps1") -Docx $docx -Pdf (Join-Path $Out "$Name.word.pdf")
$env:PYTHONIOENCODING = "utf-8"
& $py -X utf8 -I -B (Join-Path $here "check_word.py") $Pdf (Join-Path $Out "$Name.word.pdf") $Out $Name
