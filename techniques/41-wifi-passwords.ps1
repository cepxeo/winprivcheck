[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'WIFI PASSWORDS'
((netsh.exe wlan show profiles) -match '\s{2,}:\s').Replace('    All User Profile     : ', '') |
  ForEach-Object { netsh wlan show profile name="$_" key=clear }
