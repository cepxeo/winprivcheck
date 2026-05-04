[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'CLIPBOARD TEXT'
try {
  Add-Type -AssemblyName PresentationCore
  $text = [Windows.Clipboard]::GetText()
  if ($text) { Write-Host $text } else { Write-Host 'Clipboard has no text.' }
}
catch {
  Write-Warning 'Unable to read clipboard text in this session.'
}
