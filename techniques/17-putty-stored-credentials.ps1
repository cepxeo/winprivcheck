[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'PUTTY STORED CREDENTIALS CHECK'
$path = 'HKCU:\SOFTWARE\SimonTatham\PuTTY\Sessions'
if (-not (Test-Path $path)) { Write-Host 'No PuTTY sessions found.'; return }
Get-ChildItem $path | ForEach-Object {
  $session = Split-Path $_.Name -Leaf
  $props = Get-ItemProperty $_.PsPath
  [pscustomobject]@{
    Session           = $session
    HostName          = $props.HostName
    PortNumber        = $props.PortNumber
    UserName          = $props.UserName
    PublicKeyFile     = $props.PublicKeyFile
    PortForwardings   = $props.PortForwardings
    ConnectionSharing = $props.ConnectionSharing
    ProxyUsername     = $props.ProxyUsername
    ProxyPassword     = $props.ProxyPassword
  }
} | Format-List
