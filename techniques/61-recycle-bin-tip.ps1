[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'RECYCLE BIN TIP'
Write-Host 'If credentials are found in the recycle bin, password recovery utilities may assist with supported file types.' -ForegroundColor Yellow
