[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'ARP TABLE'
Start-Process arp -ArgumentList '-A' -Wait -NoNewWindow
Write-PrivCheckSection 'ROUTES'
Start-Process route -ArgumentList 'print' -Wait -NoNewWindow
Write-PrivCheckSection 'NETWORK ADAPTERS'
Get-NetAdapter -ErrorAction SilentlyContinue |
  Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress |
  Format-Table -AutoSize -Wrap
