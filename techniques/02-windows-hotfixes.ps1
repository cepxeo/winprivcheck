[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'WINDOWS HOTFIXES'
Get-HotFix -ErrorAction SilentlyContinue |
  Sort-Object -Descending -Property InstalledOn |
  Select-Object HotfixID, Description, InstalledBy, InstalledOn |
  Format-Table -AutoSize
