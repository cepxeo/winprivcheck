[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'LSA PROTECTION CHECK'
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -ErrorAction SilentlyContinue
switch ($lsa.RunAsPPL) {
  2 { Write-Host 'RunAsPPL: 2. Enabled without UEFI lock.' }
  1 { Write-Host 'RunAsPPL: 1. Enabled with UEFI lock.' }
  0 { Write-Host 'RunAsPPL: 0. LSA protection disabled.' -ForegroundColor Red }
  default { Write-Host 'RunAsPPL registry value not found.' }
}
if ($null -ne $lsa.RunAsPPLBoot) { Write-Host "RunAsPPLBoot: $($lsa.RunAsPPLBoot)" }
