Set-StrictMode -Version Latest

function Write-Section {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title
    )

    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Get-ConfigurationNamingContext {
    [CmdletBinding()]
    param(
        [string]$DomainController
    )

    try {
        if ($DomainController) {
            $root = [ADSI]"LDAP://$DomainController/RootDSE"
        }
        else {
            $root = [ADSI]"LDAP://RootDSE"
        }

        return [string]$root.configurationNamingContext
    }
    catch {
        throw "Unable to query RootDSE. Ensure domain connectivity and permissions. $($_.Exception.Message)"
    }
}

function Search-Ldap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LdapPath,

        [Parameter(Mandatory = $true)]
        [string]$Filter,

        [string[]]$Properties = @("*")
    )

    $entry = New-Object System.DirectoryServices.DirectoryEntry($LdapPath)
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $searcher.Filter = $Filter
    $searcher.PageSize = 200

    foreach ($prop in $Properties) {
        [void]$searcher.PropertiesToLoad.Add($prop)
    }

    return $searcher.FindAll()
}

function Convert-SearchResultToObject {
    param(
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.SearchResult]$Result
    )

    $obj = [ordered]@{}

    foreach ($propertyName in $Result.Properties.PropertyNames) {
        $values = @($Result.Properties[$propertyName])
        if ($values.Count -eq 1) {
            $obj[$propertyName] = $values[0]
        }
        else {
            $obj[$propertyName] = $values
        }
    }

    [pscustomobject]$obj
}

function Test-TemplateRisk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Template
    )

    $riskFlags = New-Object System.Collections.Generic.List[string]
    $nameFlags = [string]$Template.'mspki-certificate-name-flag'
    $enrollFlags = [string]$Template.'mspki-enrollment-flag'
    $eku = @($Template.'pkiextendedkeyusage')

    if ($nameFlags -match "1|65536") {
        $riskFlags.Add("Potential SAN supply in request flag")
    }

    if ($enrollFlags -match "2|32") {
        $riskFlags.Add("Potential manager approval bypass/misuse risk")
    }

    if ($eku.Count -eq 0) {
        $riskFlags.Add("Any purpose/no EKU style template behavior")
    }

    return [pscustomobject]@{
        TemplateName = [string]$Template.name
        DisplayName  = [string]$Template.displayname
        Enabled      = -not [string]::IsNullOrWhiteSpace([string]$Template.name)
        RiskCount    = $riskFlags.Count
        RiskFlags    = @($riskFlags.ToArray())
    }
}

function Export-DefensiveReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,
        [string]$OutFile
    )

    if ([string]::IsNullOrWhiteSpace($OutFile)) {
        return
    }

    $dir = Split-Path -Path $OutFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $InputObject | ConvertTo-Json -Depth 8 | Set-Content -Path $OutFile -Encoding UTF8
    Write-Host "Report written to: $OutFile" -ForegroundColor Green
}

Export-ModuleMember -Function @(
    "Write-Section",
    "Get-ConfigurationNamingContext",
    "Search-Ldap",
    "Convert-SearchResultToObject",
    "Test-TemplateRisk",
    "Export-DefensiveReport"
)
