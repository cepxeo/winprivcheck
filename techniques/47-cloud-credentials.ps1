[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'CLOUD CREDENTIALS CHECK'
$relativePaths = @(
  '.aws\credentials',
  'AppData\Roaming\gcloud\credentials.db',
  'AppData\Roaming\gcloud\legacy_credentials',
  'AppData\Roaming\gcloud\access_tokens.db',
  '.azure\accessTokens.json',
  '.azure\azureProfile.json'
)
Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue | ForEach-Object {
  $user = $_.FullName
  foreach ($relativePath in $relativePaths) {
    $path = Join-Path $user $relativePath
    if (Test-Path $path) { Write-Host "$path found!" -ForegroundColor Red }
  }
}
