[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'POWERSHELL HISTORY PASSWORD SEARCH'
$paths = @()
try { $paths += (Get-PSReadLineOption).HistorySavePath } catch { }
$paths += "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
$paths | Sort-Object -Unique | ForEach-Object {
  if (Test-Path $_) {
    Write-Host "History file: $_" -ForegroundColor Blue
    Get-Content $_ -ErrorAction SilentlyContinue | Select-String 'pa'
  }
}
if (Test-Path "$env:SystemDrive\transcripts\") { Write-Host "Default transcripts found at $env:SystemDrive\transcripts\" }
