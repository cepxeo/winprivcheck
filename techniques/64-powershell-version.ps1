[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'POWERSHELL INFO'
'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine',
'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' | ForEach-Object {
  $version = (Get-ItemProperty $_ -ErrorAction SilentlyContinue).PowerShellVersion
  if ($version) { Write-Host "PowerShell $version available" }
}
