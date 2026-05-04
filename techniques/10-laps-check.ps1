[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'LAPS CHECK'
$dlls = @('C:\Program Files\LAPS\CSE\Admpwd.dll', 'C:\Program Files (x86)\LAPS\CSE\Admpwd.dll')
$found = $dlls | Where-Object { Test-Path $_ }
if ($found) { $found | ForEach-Object { Write-Host "LAPS DLL found: $_" -ForegroundColor Green } } else { Write-Host 'LAPS DLLs not found on this machine' }
$policy = Get-ItemProperty 'HKLM:\Software\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
if ($policy.AdmPwdEnabled -eq 1) { Write-Host 'LAPS registry key found and enabled' -ForegroundColor Green }
