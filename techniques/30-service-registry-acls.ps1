[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SERVICE REGISTRY ACLS'
Get-ChildItem 'HKLM:\System\CurrentControlSet\Services' -ErrorAction SilentlyContinue | ForEach-Object {
  $target = $_.Name.Replace('HKEY_LOCAL_MACHINE', 'HKLM:')
  Test-PrivCheckAcl -Target $target
}
