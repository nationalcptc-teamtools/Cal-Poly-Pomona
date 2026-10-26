# Prove the Word export against the PDF it was made from.
#
#   .\compare.ps1 -Source <folder-with-main.typ> -Out <scratch-folder>
#   .\compare.ps1 -Pdf <already-compiled.pdf>   -Out <scratch-folder>
#
# -Fonts <dir> [<dir> ...] adds font directories to both the compile and the
# conversion, which is what the server does: the report's own `fonts/` and the
# defaults the browser compiler ships. Without them the Word file names fonts
# it does not carry, and Word substitutes.
#
# -Raw converts with pdf2docx alone (convert.py --raw); -Skip <pass,...> turns
# the named passes off for that run (convert.py --skip).
#
# A developer tool. It is not part of `bun run test`, it never runs in Docker,
# and it needs three things this machine has and the container does not:
# typst on PATH, Microsoft Word, and the report's fonts installed so Word is
# not substituting while you look at the result.
#
# What it does: compile the PDF, run convert.py on it, render the Word file
# back to PDF through Word itself, then score the two page by page and write
# contact sheets you can open side by side. Equal page counts are the pass
# mark; the sheets are the real check.

[CmdletBinding()]
param(
  [string]$Source,
  [string]$Pdf,
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$Python = $env:PDF2DOCX_PYTHON,
  [string[]]$Fonts = @(),
  [string]$Label = "sheet",
  [switch]$Raw,
  [string]$Skip
)

$ErrorActionPreference = "Stop"
if (-not $Python) { $Python = "python" }
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$fontDirs = @($Fonts | Where-Object { $_ } | ForEach-Object { (Resolve-Path $_).Path })

# 1. The reference PDF, compiled the way the server compiles it.
$reference = Join-Path $Out "reference.pdf"
if ($Pdf) {
  Copy-Item -Force (Resolve-Path $Pdf).Path $reference
} elseif ($Source) {
  $src = (Resolve-Path $Source).Path
  $args = @("compile", "--root", $src, "--ignore-system-fonts", "-j", "1")
  $fonts = Join-Path $src "fonts"
  if (Test-Path $fonts) { $args += @("--font-path", $fonts) }
  foreach ($dir in $fontDirs) { $args += @("--font-path", $dir) }
  $args += @((Join-Path $src "main.typ"), $reference)
  & typst @args
  if ($LASTEXITCODE -ne 0) { throw "typst compile failed ($LASTEXITCODE)" }
} else {
  throw "pass -Source <folder> or -Pdf <file>"
}

# 2. The converter under test.
$docx = Join-Path $Out "converted.docx"
$result = Join-Path $Out "result.json"
$convertArgs = @("-I", "-B", (Join-Path $here "convert.py"))
foreach ($dir in $fontDirs) { $convertArgs += "--fonts=$dir" }
if ($Source -and (Test-Path (Join-Path (Resolve-Path $Source).Path "fonts"))) {
  $convertArgs += "--fonts=$((Resolve-Path (Join-Path (Resolve-Path $Source).Path 'fonts')).Path)"
}
if ($Raw) { $convertArgs += "--raw" }
if ($Skip) { $convertArgs += "--skip=$Skip" }
$convertArgs += @($reference, $docx, $result)
& $Python @convertArgs
if ($LASTEXITCODE -ne 0) { throw "convert.py failed ($LASTEXITCODE): $(Get-Content $result -Raw)" }
Write-Host "result.json: $(Get-Content $result -Raw)"

# 3. Word's own opinion of that file, as a PDF.
$rendered = Join-Path $Out "converted.pdf"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here "render_word.ps1") -Docx $docx -Pdf $rendered
if ($LASTEXITCODE -ne 0) { throw "Word could not render $docx" }

# 4. Score the pages and draw the sheets.
& $Python -I -B (Join-Path $here "compare_pages.py") $reference $rendered $Out $Label
$scored = $LASTEXITCODE
if ($scored -ne 0) { Write-Warning "page counts differ" }
exit $scored
