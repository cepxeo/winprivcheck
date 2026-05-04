[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SYSTEM INFORMATION'
Write-Host 'Curated host information. Run Get-ComputerInfo for a larger native PowerShell inventory.'
systeminfo.exe
