[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SSH KEY CHECKS'
if (Test-Path 'HKCU:\Software\SimonTatham\PuTTY\SshHostKeys') {
  Write-Host 'PuTTY SSH known-host keys found.'
  Get-Item 'HKCU:\Software\SimonTatham\PuTTY\SshHostKeys'
}
else { Write-Host 'No PuTTY SSH known-host keys found.' }

if (Test-Path 'HKCU:\Software\OpenSSH\Agent\Keys') {
  Write-Host 'OpenSSH agent keys found.' -ForegroundColor Yellow
  Get-ChildItem 'HKCU:\Software\OpenSSH\Agent\Keys' -ErrorAction SilentlyContinue
}
else { Write-Host 'No OpenSSH agent keys found.' }
