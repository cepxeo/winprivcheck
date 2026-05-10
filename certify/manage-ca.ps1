param(
    [Parameter(Mandatory = $true)]
    [string]$CAName,
    [string]$Action,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

Write-Section "CA Management Technique (Defensive Change Review)"

$analysis = [pscustomobject]@{
    Technique              = "manage-ca"
    CAName                 = $CAName
    RequestedAction        = $Action
    SimulationOnly         = $true
    ChangeControlChecklist = @(
        "Require peer approval before CA policy changes",
        "Back up CA database and configuration before modifications",
        "Alert on enrollment/security descriptor changes",
        "Capture before/after config snapshots"
    )
}

if (-not $WhatIfOnly) {
    Write-Warning "Direct CA administration actions are disabled; use controlled enterprise tooling."
}

$analysis | Format-List
Export-DefensiveReport -InputObject $analysis -OutFile $OutFile
