param(
    [Parameter(Mandatory = $true)]
    [string]$Template,
    [string]$Action,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

Write-Section "Template Management Technique (Defensive Change Review)"

$analysis = [pscustomobject]@{
    Technique              = "manage-template"
    Template               = $Template
    RequestedAction        = $Action
    SimulationOnly         = $true
    HardeningChecklist     = @(
        "Constrain enrollment ACLs to required principals",
        "Remove risky EKU combinations for privileged auth",
        "Disable subject/SAN supply unless business-justified",
        "Enable manager approval for sensitive templates"
    )
}

if (-not $WhatIfOnly) {
    Write-Warning "Template mutation is blocked in this defensive version."
}

$analysis | Format-List
Export-DefensiveReport -InputObject $analysis -OutFile $OutFile
