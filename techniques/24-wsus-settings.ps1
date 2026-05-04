[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'WSUS SETTINGS'
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$au = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
if (Test-Path $wu) { Get-Item $wu }
$props = Get-ItemProperty $au -ErrorAction SilentlyContinue
if ($props.UseWUServer) {
  Write-Host "UseWUServer: $($props.UseWUServer)"
  $server = (Get-ItemProperty $wu -ErrorAction SilentlyContinue).WUServer
  if ($server -like 'http://*') { Write-Host "WSUS uses HTTP: $server" -ForegroundColor Red }
}
else { Write-Host 'UseWUServer is not enabled or AU policy key is absent.' }
