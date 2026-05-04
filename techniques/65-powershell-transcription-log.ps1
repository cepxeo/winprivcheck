[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'POWERSHELL TRANSCRIPTION LOG CHECK'
$paths = @(
  'HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
  'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
  'HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
  'HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
)
$paths | Where-Object { Test-Path $_ } | ForEach-Object { Get-Item $_ }
