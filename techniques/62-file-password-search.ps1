[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'PASSWORD CHECK IN FILES/FOLDERS'
$extensions = '*.xml', '*.txt', '*.conf', '*.config', '*.cfg', '*.ini', '*.y*ml', '*.log', '*.bak', '*.xls', '*.xlsx', '*.xlsm'
$regexSearch = Get-PrivCheckRegexSearch -FullCheck:$FullCheck
$drives = Get-PSDrive | Where-Object { $_.Root -like '*:\' }
$readExcel = $false
if ($Excel -or $FullCheck) {
  try {
    $probe = New-Object -ComObject Excel.Application
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($probe)
    $readExcel = $true
  }
  catch { Write-Host 'Excel COM object unavailable; Excel files will only be named.' -ForegroundColor Yellow }
}
foreach ($drive in $drives.Root) {
  Get-ChildItem $drive -Recurse -Include $extensions -ErrorAction SilentlyContinue -Force | ForEach-Object {
    $path = $_.FullName
    if ($path -match '(?i)\\lang\\') { return }
    if ($path -match '(?i)pass') { Write-Host "$path contains the word pass" -ForegroundColor Blue }
    if ($path -match '(?i)user' -and $path -notmatch '(?i)\\Users\\') { Write-Host "$path contains the word user" -ForegroundColor Blue }
    if ($path -match '(?i)SiteList\.xml$') {
      Write-Host "Possible McAfee SiteList.xml found: $path" -ForegroundColor Yellow
    }
    if ($path -match '\.xlsm?$|\.xlsx$') {
      if ($readExcel) {
        Search-PrivCheckExcel -Source $path -SearchText 'user'
        Search-PrivCheckExcel -Source $path -SearchText 'pass'
      }
      continue
    }
    foreach ($name in $regexSearch.Keys) {
      $match = Get-Content $path -ErrorAction SilentlyContinue -Force | Select-String $regexSearch[$name] -Context 1, 1
      if ($match) {
        Write-Host "Possible secret found: $name" -ForegroundColor Yellow
        Write-Host $path
        $match | ForEach-Object { Write-Host $_ -ForegroundColor Red }
      }
    }
  }
}
