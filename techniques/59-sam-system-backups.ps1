[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SAM / SYSTEM BACKUP CHECKS'
$paths = @(
  "$env:windir\repair\SAM",
  "$env:windir\System32\config\RegBack\SAM",
  "$env:windir\System32\config\SAM",
  "$env:windir\repair\system",
  "$env:windir\System32\config\SYSTEM",
  "$env:windir\System32\config\RegBack\system"
)
$paths | Where-Object { Test-Path $_ -ErrorAction SilentlyContinue } | ForEach-Object { Write-Host "$_ found!" -ForegroundColor Red }
