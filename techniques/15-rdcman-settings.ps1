[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'RDCMAN SETTINGS CHECK'
$path = Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\Remote Desktop Connection Manager\RDCMan.settings'
if (Test-Path $path) { Write-Host "RDCMan settings found at: $path" -ForegroundColor Red } else { Write-Host 'No RDCMan.settings found.' }
