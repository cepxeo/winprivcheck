[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'USER DIRECTORY ACCESS CHECK'
Get-ChildItem C:\Users\* -ErrorAction SilentlyContinue | ForEach-Object {
  if (Get-ChildItem $_.FullName -ErrorAction SilentlyContinue) {
    Write-Host "Read access to $($_.FullName)" -ForegroundColor Red
  }
}
