[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'POWERSHELL SCRIPT BLOCK LOG CHECK'
$paths = @(
  'HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
)
$paths | Where-Object { Test-Path $_ } | ForEach-Object { Get-Item $_ }
