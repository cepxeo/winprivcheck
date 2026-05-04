[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'OPENVPN CREDENTIALS CHECK'
$keys = Get-ChildItem 'HKCU:\Software\OpenVPN-GUI\configs' -ErrorAction SilentlyContinue
if (-not $keys) { Write-Host 'No OpenVPN GUI config keys found.'; return }
Add-Type -AssemblyName System.Security
foreach ($key in $keys) {
  $item = Get-ItemProperty $key.PsPath
  try {
    $entropy = $item.'entropy'
    $entropy = $entropy[0..($entropy.Length - 2)]
    $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
      $item.'auth-data',
      $entropy,
      [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    Write-Host "Config: $($key.PSChildName)" -ForegroundColor Blue
    Write-Host ([System.Text.Encoding]::Unicode.GetString($bytes))
  }
  catch {
    Write-Warning "Unable to decrypt OpenVPN credentials for $($key.PSChildName)"
  }
}
