[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'RDP SAVED CONNECTIONS CHECK'
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $sid = $_.Name.Replace('HKEY_USERS\', '')
  $path = "registry::HKEY_USERS\$sid\Software\Microsoft\Terminal Server Client\Default"
  if (Test-Path $path) {
    Get-ItemProperty $path | Select-Object @{Name='Hive';Expression={$sid}}, MRU*
  }
}
$current = 'registry::HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default'
if (Test-Path $current) { Get-ItemProperty $current | Select-Object @{Name='Hive';Expression={'HKCU'}}, MRU* }
