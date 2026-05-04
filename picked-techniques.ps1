param(
  [switch]$TimeStamp,
  [switch]$FullCheck,
  [switch]$Excel,
  [string]$LogPath = (Join-Path $PSScriptRoot 'picked-techniques.log')
)

$techniquesRoot = Join-Path $PSScriptRoot 'techniques'
$techniqueNumbers = @(
  10..13
  16..22
  26..29
  31..33
  36
  39
  43
  45..62
  65..67
  74..76
)

$scriptArguments = @{}
if ($TimeStamp) { $scriptArguments.TimeStamp = $true }
if ($FullCheck) { $scriptArguments.FullCheck = $true }
if ($Excel) { $scriptArguments.Excel = $true }

$transcriptStarted = $false

try {
  Start-Transcript -Path $LogPath -Force | Out-Null
  $transcriptStarted = $true

  Write-Host ("Picked techniques started: {0}" -f (Get-Date -Format 's'))
  Write-Host ("Technique directory: {0}" -f $techniquesRoot)
  Write-Host ("Log path: {0}" -f (Resolve-Path -LiteralPath $LogPath -ErrorAction SilentlyContinue))

  foreach ($number in $techniqueNumbers) {
    $prefix = '{0:D2}' -f $number
    $script = @(Get-ChildItem -Path $techniquesRoot -Filter "$prefix-*.ps1" -File -ErrorAction SilentlyContinue | Sort-Object Name)

    if ($script.Count -eq 0) {
      Write-Warning "Technique $prefix was not found."
      continue
    }

    if ($script.Count -gt 1) {
      Write-Warning "Technique $prefix matched more than one script; running $($script[0].Name)."
    }

    Write-Host ""
    Write-Host ("===== Running {0} =====" -f $script[0].Name) -ForegroundColor Cyan

    try {
      & $script[0].FullName @scriptArguments
    }
    catch {
      Write-Warning ("Technique {0} failed: {1}" -f $script[0].Name, $_.Exception.Message)
    }
  }

  Write-Host ""
  Write-Host ("Picked techniques finished: {0}" -f (Get-Date -Format 's'))
}
finally {
  if ($transcriptStarted) {
    Stop-Transcript | Out-Null
  }
}

