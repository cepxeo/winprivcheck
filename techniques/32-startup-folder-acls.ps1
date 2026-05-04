[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'STARTUP FOLDER ACLS'
$paths = @(
  'C:\Documents and Settings\All Users\Start Menu\Programs\Startup',
  "C:\Documents and Settings\$env:USERNAME\Start Menu\Programs\Startup",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
  "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($path in $paths) {
  if (-not (Test-Path $path)) { continue }
  Test-PrivCheckAcl -Target $path
  Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Test-PrivCheckAcl -Target $_.FullName }
}
