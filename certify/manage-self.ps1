param(
    [string]$Principal,
    [switch]$WhatIfOnly = $true,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$Principal = Resolve-CertifyDefensiveEnvString -ParameterValue $Principal -EnvironmentVariableNames @('CERTIFY_PRINCIPAL')

if ([string]::IsNullOrWhiteSpace($Principal)) {
    $Principal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}

Write-CertifyDefensiveExecutionContext -DomainController $null

Write-Section "Self-Permission Technique (Defensive Principal Review)"

$analysis = [pscustomobject]@{
    Technique                = "manage-self"
    Principal                = $Principal
    SimulationOnly           = $true
    ReviewChecks             = @(
        "Validate self-enrollment rights are least-privileged",
        "Remove broad Authenticated Users template enrollment",
        "Monitor ACL changes on certificate templates"
    )
}

if (-not $WhatIfOnly) {
    Write-Warning "Self-rights modification is disabled in this defensive toolkit."
}

$analysis | Format-List
Export-DefensiveReport -InputObject $analysis -OutFile $OutFile
