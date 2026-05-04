[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'DPAPI CREDENTIAL FILES'
$roots = @(
  "C:\Users\$env:USERNAME\AppData\Roaming\Microsoft\Credentials",
  "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Credentials"
)
foreach ($root in $roots) {
  if (Test-Path $root) {
    Write-Host "Found: $root"
    Get-ChildItem -Path $root -Force -ErrorAction SilentlyContinue
  }
}
