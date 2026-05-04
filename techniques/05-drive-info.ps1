[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'DRIVE INFO'
Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction SilentlyContinue |
  Select-Object DeviceID, VolumeName,
    @{Name='SizeGB'; Expression={[math]::Round($_.Size / 1GB, 2)}},
    @{Name='FreeGB'; Expression={[math]::Round($_.FreeSpace / 1GB, 2)}} |
  Format-Table -AutoSize
