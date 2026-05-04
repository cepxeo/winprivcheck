[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'CURRENT LOGGED ON USERS'
try { quser } catch { Write-Host 'quser command not present on system.' }
Write-PrivCheckSection 'REMOTE SESSIONS'
try { qwinsta } catch { Write-Host 'qwinsta command not present on system.' }
Write-PrivCheckSection 'KERBEROS TICKETS'
try { klist } catch { Write-Host 'No active sessions or klist unavailable.' }
