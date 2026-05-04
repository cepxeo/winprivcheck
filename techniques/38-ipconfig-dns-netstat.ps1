[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'IPCONFIG ALL'
Start-Process ipconfig.exe -ArgumentList '/all' -Wait -NoNewWindow
Write-PrivCheckSection 'DNS CACHE'
ipconfig /displaydns | Select-String 'Record' | ForEach-Object { Write-Host $_ }
Write-PrivCheckSection 'LISTENING PORTS'
Start-Process netstat.exe -ArgumentList '-ano' -Wait -NoNewWindow
