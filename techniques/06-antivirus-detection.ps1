[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'ANTIVIRUS DETECTION'
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
  Select-Object displayName, pathToSignedProductExe, productState |
  Format-Table -AutoSize
Write-PrivCheckSection 'WINDOWS DEFENDER EXCLUSIONS'
Get-ChildItem 'registry::HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -ErrorAction SilentlyContinue
