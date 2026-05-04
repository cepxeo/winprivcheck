[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'NETWORK ADAPTERS'
Get-NetAdapter -ErrorAction SilentlyContinue |
  Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress |
  Format-Table -AutoSize -Wrap
