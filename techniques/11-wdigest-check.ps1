[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'WDIGEST CHECK'
$value = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
switch ($value) {
  0 { Write-Host 'UseLogonCredential is 0. Plain-text passwords are not stored in LSASS.' }
  1 { Write-Host 'UseLogonCredential is 1. Plain-text passwords may be stored in LSASS.' -ForegroundColor Red }
  default { Write-Host 'UseLogonCredential registry value not found.' }
}
