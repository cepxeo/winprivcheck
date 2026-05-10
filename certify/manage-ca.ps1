param(
    [string]$CAName,
    [string]$Action,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$CAName = Resolve-CertifyDefensiveEnvString -ParameterValue $CAName -EnvironmentVariableNames @('CERTIFY_CA_NAME')
$Action = Resolve-CertifyDefensiveEnvString -ParameterValue $Action -EnvironmentVariableNames @('CERTIFY_MANAGE_ACTION')

if ([string]::IsNullOrWhiteSpace($CAName)) {
    throw "CAName is required. Use -CAName or set CERTIFY_CA_NAME."
}

Write-CertifyDefensiveExecutionContext -DomainController $null

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
