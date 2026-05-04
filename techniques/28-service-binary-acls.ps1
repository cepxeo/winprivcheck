[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SERVICE BINARY ACLS'
$unique = @{}
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.PathName -like '*.exe*' } |
  ForEach-Object {
    $path = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"')
    if ($path) { $unique[$path] = $_.Name }
  }
foreach ($entry in $unique.GetEnumerator()) {
  Test-PrivCheckAcl -Target $entry.Key -ServiceName $entry.Value
}
