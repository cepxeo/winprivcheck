[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'APPCMD CHECK'
$path = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
if (Test-Path $path) { Write-Host "$path exists!" -ForegroundColor Red } else { Write-Host 'appcmd.exe not found.' }
