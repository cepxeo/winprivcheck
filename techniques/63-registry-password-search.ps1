[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'REGISTRY PASSWORD CHECK'
$regexSearch = Get-PrivCheckRegexSearch -FullCheck:$FullCheck
foreach ($root in 'registry::HKEY_CURRENT_USER\', 'registry::HKEY_LOCAL_MACHINE\') {
  Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $key = $_
    foreach ($property in $key.Property) {
      foreach ($name in $regexSearch.Keys) {
        $pattern = $regexSearch[$name]
        if ($property -match $pattern) {
          Write-Host "Possible secret property: $($key.Name)\$property ($name)" -ForegroundColor Red
        }
        try { $value = (Get-ItemProperty "registry::$($key.Name)" -ErrorAction Stop).$property } catch { continue }
        if ($value -and ($value.ToString() -match $pattern)) {
          Write-Host "Possible secret value: $($key.Name)\$property ($name) = $value" -ForegroundColor Red
        }
      }
    }
  }
  Write-Host "Finished $root"
}
