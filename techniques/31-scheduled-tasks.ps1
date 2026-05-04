[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SCHEDULED TASKS'
$taskFolder = 'C:\Windows\System32\Tasks'
if (Get-ChildItem $taskFolder -ErrorAction SilentlyContinue) {
  Write-Host 'Access confirmed to scheduled tasks folder. Listing tasks on disk:'
  Get-ChildItem $taskFolder -ErrorAction SilentlyContinue
}
else {
  Write-Host 'No admin access to scheduled tasks folder. Checking visible non-Microsoft tasks.'
}
Get-ScheduledTask -ErrorAction SilentlyContinue |
  Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
  ForEach-Object {
    $task = $_
    foreach ($action in @($task.Actions)) {
      $command = $action.Execute
      if (-not $command) { continue }
      $expanded = $command -replace '%windir%', $env:windir
      $expanded = $expanded -replace '%SystemRoot%', $env:windir
      $expanded = $expanded -replace '%localappdata%', "$env:USERPROFILE\AppData\Local"
      $expanded = $expanded -replace '%appdata%', $env:APPDATA
      $expanded = ($expanded -split '(?<=\.exe\b)')[0].Trim('"')
      Test-PrivCheckAcl -Target $expanded
      $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
      [pscustomobject]@{
        TaskName   = $task.TaskName
        LastResult = $info.LastTaskResult
        NextRun    = $info.NextRunTime
        Status     = $task.State
        Command    = $action.Execute
        Arguments  = $action.Arguments
      }
    }
  } | Format-Table -AutoSize -Wrap
