param(
    [string]$CAName,
    $RequestId,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$CAName = Resolve-CertifyDefensiveEnvString -ParameterValue $CAName -EnvironmentVariableNames @('CERTIFY_CA_NAME')

$requestIdFromParam = $null
if ($PSBoundParameters.ContainsKey('RequestId') -and $null -ne $RequestId -and "$RequestId" -ne '') {
    $requestIdFromParam = [int]$RequestId
}

$RequestId = Resolve-CertifyDefensiveEnvInt -ParameterValue $requestIdFromParam -EnvironmentVariableNames @('CERTIFY_REQUEST_ID')

if ([string]::IsNullOrWhiteSpace($CAName) -or $null -eq $RequestId) {
    throw "CAName and RequestId are required. Use parameters or set CERTIFY_CA_NAME and CERTIFY_REQUEST_ID."
}

Write-CertifyDefensiveExecutionContext -DomainController $null

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
