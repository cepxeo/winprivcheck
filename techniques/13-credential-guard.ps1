[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'CREDENTIAL GUARD CHECK'
$value = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -ErrorAction SilentlyContinue).LsaCfgFlags
switch ($value) {
  2 { Write-Host 'LsaCfgFlags: 2. Enabled without UEFI lock.' }
  1 { Write-Host 'LsaCfgFlags: 1. Enabled with UEFI lock.' }
  0 { Write-Host 'LsaCfgFlags: 0. Credential Guard disabled.' -ForegroundColor Red }
  default { Write-Host 'LsaCfgFlags registry value not found.' }
}
