[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'STARTUP REGISTRY ACLS'
$runKeys = @(
  'registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run',
  'registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run',
  'registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
  if (-not (Test-Path $key)) { continue }
  $item = Get-Item $key -ErrorAction SilentlyContinue
  foreach ($property in $item.Property) {
    $value = (Get-ItemProperty -Path $key).$property
    $path = ($value -split '(?<=\.exe\b)')[0].Trim('"')
    if ($path) { Test-PrivCheckAcl -Target $path }
  }
}
