[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'ENVIRONMENT VARIABLES'
Write-Host 'Review PATH entries for writable locations that could support binary or DLL hijacking.'
Get-ChildItem env: | Format-Table -Wrap
