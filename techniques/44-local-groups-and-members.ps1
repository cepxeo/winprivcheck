[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'LOCAL GROUPS AND MEMBERS'
Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Host ""
  Write-Host "Group: $($_.Name)"
  $members = Get-LocalGroupMember -Name $_.Name -ErrorAction SilentlyContinue
  if ($members) { $members | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -AutoSize }
  else { Write-Host '     {GROUP EMPTY}' }
}
