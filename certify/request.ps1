param(
    [Parameter(Mandatory = $true)]
    [string]$CAName,
    [Parameter(Mandatory = $true)]
    [string]$Template,
    [string]$Subject,
    [string]$San,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

Write-Section "Certificate Request Technique (Defensive Simulation)"

$analysis = [pscustomobject]@{
    Technique            = "request"
    CAName               = $CAName
    Template             = $Template
    Subject              = $Subject
    SubjectAltName       = $San
    SimulationOnly       = $true
    RecommendedControls  = @(
        "Restrict enrollment rights on high-risk templates",
        "Require manager approval for privileged templates",
        "Disable SAN supply where not required",
        "Enable CA auditing for request and issuance events"
    )
}

if (-not $WhatIfOnly) {
    Write-Warning "Non-simulated enrollment is intentionally blocked in this defensive reimplementation."
}

$analysis | Format-List
Export-DefensiveReport -InputObject $analysis -OutFile $OutFile
