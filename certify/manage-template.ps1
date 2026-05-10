param(
    [string]$Template,
    [string]$Action,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$Template = Resolve-CertifyDefensiveEnvString -ParameterValue $Template -EnvironmentVariableNames @('CERTIFY_TEMPLATE')
$Action = Resolve-CertifyDefensiveEnvString -ParameterValue $Action -EnvironmentVariableNames @('CERTIFY_MANAGE_ACTION')

if ([string]::IsNullOrWhiteSpace($Template)) {
    throw "Template is required. Use -Template or set CERTIFY_TEMPLATE."
}

Write-CertifyDefensiveExecutionContext -DomainController $null

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
