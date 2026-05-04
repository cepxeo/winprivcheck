[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'ALWAYS INSTALL ELEVATED CHECK'
$paths = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer', 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer'
foreach ($path in $paths) {
  $value = (Get-ItemProperty $path -ErrorAction SilentlyContinue).AlwaysInstallElevated
  if ($value -eq 1) {
    Write-Host "$path AlwaysInstallElevated = 1" -ForegroundColor Red
  }
  else {
    Write-Host "$path AlwaysInstallElevated is not enabled."
  }
}
