[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'WINDOWS EVENT FORWARDING REGISTRY'
$path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
if (Test-Path $path) { Get-Item $path } else { Write-Host 'Logs are not being forwarded; no registry entry found.' }
