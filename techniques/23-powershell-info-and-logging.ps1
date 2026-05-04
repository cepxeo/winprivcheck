[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'POWERSHELL INFO AND LOGGING'
'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine',
'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine' | ForEach-Object {
  $version = (Get-ItemProperty $_ -ErrorAction SilentlyContinue).PowerShellVersion
  if ($version) { Write-Host "PowerShell $version available" }
}
$loggingPaths = @(
  'HKCU:\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
  'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
  'HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKCU:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
  'HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\Transcription',
  'HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKCU:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'HKLM:\Wow6432Node\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
)
foreach ($path in $loggingPaths) {
  if (Test-Path $path) { Get-Item $path }
}
