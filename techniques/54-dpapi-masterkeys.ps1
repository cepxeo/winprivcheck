[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'DPAPI MASTERKEYS'
$roots = @(
  "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Protect",
  "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Protect"
)
foreach ($root in $roots) {
  if (Test-Path $root) {
    Write-Host "Found: $root"
    Get-ChildItem -Path $root -Force -ErrorAction SilentlyContinue | Select-Object FullName
  }
}
