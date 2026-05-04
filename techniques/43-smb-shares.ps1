[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'SMB SHARES'
$identities = Get-PrivCheckIdentities
Get-SmbShare -ErrorAction SilentlyContinue |
  Get-SmbShareAccess -ErrorAction SilentlyContinue |
  ForEach-Object {
    $access = $_
    if (($identities | Where-Object { $access.AccountName -like $_ }) -and $access.AccessControlType -eq 'Allow' -and $access.AccessRight -in @('Full', 'Change')) {
      Write-Host ("{0} has {1} access to {2}" -f $access.AccountName, $access.AccessRight, $access.Name) -ForegroundColor Red
    }
    else { $access }
  }
