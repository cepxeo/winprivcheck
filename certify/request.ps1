param(
    [string]$CAName,
    [string]$Template,
    [string]$Subject,
    [string]$San,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$CAName = Resolve-CertifyDefensiveEnvString -ParameterValue $CAName -EnvironmentVariableNames @('CERTIFY_CA_NAME')
$Template = Resolve-CertifyDefensiveEnvString -ParameterValue $Template -EnvironmentVariableNames @('CERTIFY_TEMPLATE')
$Subject = Resolve-CertifyDefensiveEnvString -ParameterValue $Subject -EnvironmentVariableNames @('CERTIFY_SUBJECT')
$San = Resolve-CertifyDefensiveEnvString -ParameterValue $San -EnvironmentVariableNames @('CERTIFY_SAN')

if ([string]::IsNullOrWhiteSpace($CAName) -or [string]::IsNullOrWhiteSpace($Template)) {
    throw "CAName and Template are required. Pass -CAName / -Template or set CERTIFY_CA_NAME and CERTIFY_TEMPLATE."
}

Write-CertifyDefensiveExecutionContext -DomainController $null

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
