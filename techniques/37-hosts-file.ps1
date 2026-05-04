[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'HOSTS FILE'
Get-Content 'C:\Windows\System32\drivers\etc\hosts' -ErrorAction SilentlyContinue
