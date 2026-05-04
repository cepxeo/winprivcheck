[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'GROUP POLICY PASSWORD CHECK'
$names = 'Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml'
$roots = @(
  "$env:SystemDrive\Microsoft\Group Policy\history",
  "$env:SystemDrive\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history"
)
foreach ($root in $roots) {
  if (Test-Path $root) {
    Get-ChildItem -Path $root -Recurse -Force -Include $names -ErrorAction SilentlyContinue
  }
}
