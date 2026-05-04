[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'UNATTENDED FILES CHECK'
$paths = @(
  'C:\Windows\sysprep\sysprep.xml',
  'C:\Windows\sysprep\sysprep.inf',
  'C:\Windows\sysprep.inf',
  'C:\Windows\Panther\Unattended.xml',
  'C:\Windows\Panther\Unattend.xml',
  'C:\Windows\Panther\Unattend\Unattend.xml',
  'C:\Windows\Panther\Unattend\Unattended.xml',
  'C:\Windows\System32\Sysprep\unattend.xml',
  'C:\Windows\System32\Sysprep\unattended.xml',
  'C:\unattend.txt',
  'C:\unattend.inf'
)
$paths | Where-Object { Test-Path $_ } | ForEach-Object { Write-Host "$_ found." -ForegroundColor Red }
