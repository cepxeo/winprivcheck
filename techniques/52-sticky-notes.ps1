[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'STICKY NOTES CHECK'
$pattern = "C:\Users\$env:USERNAME\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes*\LocalState\plum.sqlite"
$matches = Get-ChildItem $pattern -ErrorAction SilentlyContinue
if ($matches) { $matches | ForEach-Object { Write-Host "Sticky Notes database found: $($_.FullName)" -ForegroundColor Yellow } }
else { Write-Host 'Sticky Notes database not found for current user.' }
