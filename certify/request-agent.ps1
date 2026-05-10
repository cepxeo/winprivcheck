param(
    [Parameter(Mandatory = $true)]
    [string]$CAName,
    [Parameter(Mandatory = $true)]
    [string]$AgentTemplate,
    [Parameter(Mandatory = $true)]
    [string]$TargetTemplate,
    [string]$OnBehalfOf,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

Write-Section "Enrollment Agent Technique (Defensive Simulation)"

$analysis = [pscustomobject]@{
    Technique           = "request-agent"
    CAName              = $CAName
    AgentTemplate       = $AgentTemplate
    TargetTemplate      = $TargetTemplate
    OnBehalfOf          = $OnBehalfOf
    SimulationOnly      = $true
    DetectionFocus      = @(
        "Track enrollment agent certificate issuance",
        "Alert on unusual target principals in on-behalf requests",
        "Restrict certificate request agent EKU templates"
    )
}

if (-not $WhatIfOnly) {
    Write-Warning "On-behalf enrollment execution is blocked; this script is audit/simulation only."
}

$analysis | Format-List
Export-DefensiveReport -InputObject $analysis -OutFile $OutFile
