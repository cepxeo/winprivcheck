[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'PRINTNIGHTMARE POINTANDPRINT POLICY'
$key = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
if (-not (Test-Path $key)) {
  Write-Host 'PointAndPrint policy key not found' -ForegroundColor Gray
  return
}
$policy = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
$restrict = $policy.RestrictDriverInstallationToAdministrators
$noWarn = $policy.NoWarningNoElevationOnInstall
$updatePrompt = $policy.UpdatePromptSettings
Write-Host "RestrictDriverInstallationToAdministrators: $restrict"
Write-Host "NoWarningNoElevationOnInstall: $noWarn"
Write-Host "UpdatePromptSettings: $updatePrompt"
if ($null -eq $restrict -or $null -eq $noWarn -or $null -eq $updatePrompt) {
  Write-Host 'PointAndPrint policy values are missing or not configured' -ForegroundColor Gray
}
elseif ($restrict -eq 0 -and $noWarn -eq 1 -and $updatePrompt -eq 2) {
  Write-Host 'Potentially vulnerable to PrintNightmare misconfiguration' -ForegroundColor Red
}
else {
  Write-Host 'PointAndPrint policy is not in the known risky configuration' -ForegroundColor Green
}
