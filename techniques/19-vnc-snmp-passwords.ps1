[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'VNC AND SNMP PASSWORD CHECKS'
$paths = @(
  'HKCU:\Software\ORL\WinVNC3',
  'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP',
  'HKCU:\Software\TightVNC\Server'
)
foreach ($path in $paths) {
  if (Test-Path $path) {
    Write-Host "$path found." -ForegroundColor Red
    Get-Item $path -ErrorAction SilentlyContinue
  }
  else { Write-Host "$path not found." }
}
