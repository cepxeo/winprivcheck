[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'UNQUOTED SERVICE PATHS'
$services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '"' -and
    $_.PathName -notmatch ':\\Windows\\' -and
    $_.PathName -match '\s' -and
    $_.StartMode -in @('Auto', 'Manual') -and
    $_.State -in @('Running', 'Stopped')
  } |
  Select-Object Name, PathName, StartName, StartMode, State
if ($services) { $services | Format-Table -AutoSize -Wrap } else { Write-Host 'No unquoted service paths were found.' }
