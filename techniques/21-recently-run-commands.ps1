[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'RECENTLY RUN COMMANDS'
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
$paths = @('HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU')
$paths += Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
  $sid = $_.Name.Replace('HKEY_USERS\', '')
  "HKU:\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
}
$paths | ForEach-Object {
  if (Test-Path $_) {
    $item = Get-Item $_ -ErrorAction SilentlyContinue
    foreach ($property in $item.Property) {
      [pscustomobject]@{ Path = $_; Name = $property; Value = $item.GetValue($property) }
    }
  }
} | Format-Table -AutoSize -Wrap
