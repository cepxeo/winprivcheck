[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'ALL UPDATES INSTALLED'
try {
  $session = New-Object -ComObject 'Microsoft.Update.Session'
  $history = $session.QueryHistory('', 0, 1000) | Select-Object ResultCode, Date, Title
}
catch {
  Write-Warning 'Unable to query Windows Update COM history.'
  return
}
$seen = @{}
$history | ForEach-Object {
  $id = Get-PrivCheckHotFixId -Title $_.Title
  if ($seen.ContainsKey($id)) { return }
  $seen[$id] = $true
  $result = switch ($_.ResultCode) {
    1 { 'Missing/Superseded' }
    2 { 'Succeeded' }
    3 { 'Succeeded With Errors' }
    4 { 'Failed' }
    5 { 'Canceled' }
    default { $_.ResultCode }
  }
  [pscustomobject]@{ Result = $result; Date = $_.Date; Title = $_.Title }
} | Format-Table -AutoSize
