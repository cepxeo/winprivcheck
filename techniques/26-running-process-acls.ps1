[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'RUNNING PROCESS ACLS'
Get-Process |
  Where-Object { $_.Path } |
  Select-Object -ExpandProperty Path -Unique |
  ForEach-Object { Test-PrivCheckAcl -Target $_ }
