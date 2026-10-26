# One Word file to PDF through Word itself, for scoring. A developer tool:
# needs Microsoft Word, never runs in Docker.
#
#   .\render_word.ps1 -Docx <in.docx> -Pdf <out.pdf>
#
# Prints "pages: N" and exits 0, or exits 1 with the error. Word is always
# closed and released, so a failed render does not leave WINWORD.EXE holding
# the next document.
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Docx,
  [Parameter(Mandatory = $true)][string]$Pdf
)
$ErrorActionPreference = "Stop"
$Docx = (Resolve-Path $Docx).Path
if (Test-Path $Pdf) { Remove-Item -Force $Pdf }
$Pdf = [System.IO.Path]::GetFullPath($Pdf)
$word = $null
$doc = $null
$code = 0
try {
  $word = New-Object -ComObject Word.Application
  $word.Visible = $false
  $word.DisplayAlerts = 0
  # FileName, ConfirmConversions, ReadOnly, AddToRecentFiles.
  $doc = $word.Documents.Open($Docx, $false, $true, $false)
  $doc.Fields.Update() | Out-Null
  $doc.Repaginate()
  $pages = $doc.ComputeStatistics(2)  # wdStatisticPages
  $doc.SaveAs2([string]$Pdf, 17)      # wdFormatPDF
  Write-Output "pages: $pages"
} catch {
  [Console]::Error.WriteLine($_.ToString())
  $code = 1
} finally {
  # Each step in its own try, so a throw in one (a document Word already
  # closed, say) cannot skip the Quit or the releases after it.
  if ($doc) { try { $doc.Close([ref]0) | Out-Null } catch { [Console]::Error.WriteLine("close: $_") } }
  if ($word) { try { $word.Quit() | Out-Null } catch { [Console]::Error.WriteLine("quit: $_") } }
  foreach ($o in @($doc, $word)) {
    if ($o) {
      try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($o) }
      catch { [Console]::Error.WriteLine("release: $_") }
    }
  }
  [System.GC]::Collect()
  [System.GC]::WaitForPendingFinalizers()
}
exit $code
