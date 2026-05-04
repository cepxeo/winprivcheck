[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'WINLOGON CREDENTIALS CHECK'
$path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (-not (Test-Path $path)) { Write-Host 'Winlogon registry key not found.'; return }
$props = Get-ItemProperty $path
[pscustomobject]@{
  CachedLogonsCount    = $props.CachedLogonsCount
  DefaultDomainName    = $props.DefaultDomainName
  DefaultUserName      = $props.DefaultUserName
  DefaultPassword      = $props.DefaultPassword
  AltDefaultDomainName = $props.AltDefaultDomainName
  AltDefaultUserName   = $props.AltDefaultUserName
  AltDefaultPassword   = $props.AltDefaultPassword
} | Format-List
Write-Host 'Only SYSTEM can normally read cached credential material under HKEY_LOCAL_MACHINE\SECURITY\Cache.'
