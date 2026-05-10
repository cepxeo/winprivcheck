param(
    [string]$CAName,
    [string]$AgentTemplate,
    [string]$TargetTemplate,
    [string]$OnBehalfOf,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$CAName = Resolve-CertifyDefensiveEnvString -ParameterValue $CAName -EnvironmentVariableNames @('CERTIFY_CA_NAME')
$AgentTemplate = Resolve-CertifyDefensiveEnvString -ParameterValue $AgentTemplate -EnvironmentVariableNames @('CERTIFY_AGENT_TEMPLATE')
$TargetTemplate = Resolve-CertifyDefensiveEnvString -ParameterValue $TargetTemplate -EnvironmentVariableNames @('CERTIFY_TARGET_TEMPLATE')
$OnBehalfOf = Resolve-CertifyDefensiveEnvString -ParameterValue $OnBehalfOf -EnvironmentVariableNames @('CERTIFY_ON_BEHALF_OF')

if ([string]::IsNullOrWhiteSpace($CAName) -or [string]::IsNullOrWhiteSpace($AgentTemplate) -or [string]::IsNullOrWhiteSpace($TargetTemplate)) {
    throw "CAName, AgentTemplate, and TargetTemplate are required. Use parameters or CERTIFY_CA_NAME, CERTIFY_AGENT_TEMPLATE, CERTIFY_TARGET_TEMPLATE."
}

Write-CertifyDefensiveExecutionContext -DomainController $null

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
