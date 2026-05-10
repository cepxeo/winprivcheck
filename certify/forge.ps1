param(
    [string]$CAName,
    [string]$TargetIdentity,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

Write-Section "Certificate Forgery Technique (Defensive Risk Assessment)"

$analysis = [pscustomobject]@{
    Technique          = "forge"
    CAName             = $CAName
    TargetIdentity     = $TargetIdentity
    SimulationOnly     = $true
    CriticalControls   = @(
        "Protect CA private keys in HSM where possible",
        "Restrict key backup/export permissions",
        "Monitor CA key access and signing operations",
        "Rotate compromised CA and revoke issued certs"
    )
}

if (-not $WhatIfOnly) {
    Write-Warning "Certificate forging is explicitly prohibited and disabled."
}

$analysis | Format-List
Export-DefensiveReport -InputObject $analysis -OutFile $OutFile
