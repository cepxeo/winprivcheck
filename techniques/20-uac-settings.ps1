[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'UAC SETTINGS'
$value = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).EnableLUA
if ($value -eq 1) {
  Write-Host 'EnableLUA is 1. UAC components are enabled.'
}
else {
  Write-Host "EnableLUA is $value. UAC may be disabled or not configured as expected." -ForegroundColor Red
}
