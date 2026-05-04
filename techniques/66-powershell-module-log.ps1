[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'POWERSHELL MODULE LOG CHECK'
$paths = @(
  'HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
)
$paths | Where-Object { Test-Path $_ } | ForEach-Object { Get-Item $_ }
