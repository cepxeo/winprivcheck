param(
    [Parameter(Mandatory = $true)]
    [string]$CAName,
    [Parameter(Mandatory = $true)]
    [int]$RequestId,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

Write-Section "Issued Certificate Retrieval Technique (Defensive Simulation)"

$analysis = [pscustomobject]@{
    Technique            = "request-download"
    CAName               = $CAName
    RequestId            = $RequestId
    SimulationOnly       = $true
    DefensiveChecks      = @(
        "Validate requester identity vs request owner",
        "Audit retrieval attempts for pending/denied IDs",
        "Restrict access to certsrv enrollment endpoints"
    )
}

if (-not $WhatIfOnly) {
    Write-Warning "Certificate download is intentionally disabled in this defensive toolkit."
}

$analysis | Format-List
Export-DefensiveReport -InputObject $analysis -OutFile $OutFile
