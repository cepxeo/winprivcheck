[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'FIREWALL RULE COMMAND'
Write-Host 'The original script prints this command instead of dumping all rules because output can be large:'
Write-Host 'netsh advfirewall firewall show rule dir=in name=all' -ForegroundColor Blue
