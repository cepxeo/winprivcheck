[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SCCM CLIENT'
$apps = Get-CimInstance -Namespace root/ccm/clientSDK -ClassName CCM_Application -Property * -ErrorAction SilentlyContinue |
  Select-Object Name, SoftwareVersion
if ($apps) { $apps }
elseif (Test-Path 'C:\Windows\CCM\SCClient.exe') { Write-Host 'SCCM Client found at C:\Windows\CCM\SCClient.exe' -ForegroundColor Cyan }
else { Write-Host 'Not installed or not visible with current privileges.' }
