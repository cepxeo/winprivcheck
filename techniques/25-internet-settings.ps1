[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'INTERNET SETTINGS HKCU / HKLM'
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings',
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | ForEach-Object {
  if (Test-Path $_) {
    $item = Get-Item $_ -ErrorAction SilentlyContinue
    foreach ($property in $item.Property) {
      [pscustomobject]@{ Path = $_; Name = $property; Value = $item.GetValue($property) }
    }
  }
} | Format-Table -AutoSize -Wrap
