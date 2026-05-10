Set-StrictMode -Version Latest

# Environment variables (optional; effective value = process, then user, then machine):
#   CERTIFY_DC, CERTIFY_DEFENSIVE_DC, CERTIFY_DOMAIN_CONTROLLER — optional LDAP host override (DC DNS name)
#   If none are set, the DC that answers LDAP RootDSE (dnsHostName) is used automatically.
#   CERTIFY_CA_NAME, CERTIFY_TEMPLATE, CERTIFY_AGENT_TEMPLATE, CERTIFY_TARGET_TEMPLATE,
#   CERTIFY_ON_BEHALF_OF, CERTIFY_REQUEST_ID, CERTIFY_CERT_THUMBPRINT, CERTIFY_SUBJECT,
#   CERTIFY_SAN, CERTIFY_MANAGE_ACTION, CERTIFY_PRINCIPAL, CERTIFY_TARGET_IDENTITY
# LDAP uses integrated auth (current Windows logon / process token); no alternate credentials.

function Get-CertifyDefensiveDiscoveredDomainControllerDns {
    # Same LDAP connection Windows uses by default — dnsHostName is the answering DC's FQDN.
    # Optional RSAT cmdlet (if installed): (Get-ADDomainController -Discover -Service GlobalCatalog).Hostname
    $auth = [System.DirectoryServices.AuthenticationTypes]::Negotiate
    try {
        $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE", $null, $null, $auth)
        $dnsProp = $root.Properties["dnsHostName"]
        if ($null -eq $dnsProp -or $dnsProp.Count -lt 1) {
            return $null
        }
        return ([string]$dnsProp[0]).Trim()
    }
    catch {
        return $null
    }
}

function Resolve-CertifyDefensiveDomainController {
    [CmdletBinding()]
    param(
        [string]$DomainControllerParameter
    )

    if (-not [string]::IsNullOrWhiteSpace($DomainControllerParameter)) {
        return $DomainControllerParameter.Trim()
    }

    foreach ($name in @('CERTIFY_DC', 'CERTIFY_DEFENSIVE_DC', 'CERTIFY_DOMAIN_CONTROLLER')) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($v)) {
            return $v.Trim()
        }
    }

    return Get-CertifyDefensiveDiscoveredDomainControllerDns
}

function Resolve-CertifyDefensiveEnvString {
    [CmdletBinding()]
    param(
        [string]$ParameterValue,
        [Parameter(Mandatory = $true)]
        [string[]]$EnvironmentVariableNames
    )

    if (-not [string]::IsNullOrWhiteSpace($ParameterValue)) {
        return $ParameterValue.Trim()
    }

    foreach ($name in $EnvironmentVariableNames) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($v)) {
            return $v.Trim()
        }
    }

    return [string]::Empty
}

function Resolve-CertifyDefensiveEnvInt {
    [CmdletBinding()]
    param(
        $ParameterValue,
        [Parameter(Mandatory = $true)]
        [string[]]$EnvironmentVariableNames
    )

    if ($null -ne $ParameterValue) {
        return [int]$ParameterValue
    }

    foreach ($name in $EnvironmentVariableNames) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrWhiteSpace($v)) {
            $parsed = 0
            if ([int]::TryParse($v.Trim(), [ref]$parsed)) {
                return $parsed
            }
        }
    }

    return $null
}

function Write-CertifyDefensiveExecutionContext {
    [CmdletBinding()]
    param(
        [string]$DomainController
    )

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Host "Security context: $($identity.Name) (Negotiate / current process token)" -ForegroundColor DarkGray

    if ([string]::IsNullOrWhiteSpace($DomainController)) {
        Write-Host "LDAP server:      not resolved (domain/RootDSE unavailable); default naming paths only" -ForegroundColor DarkGray
    }
    else {
        Write-Host "LDAP server:      $DomainController (-DomainController / CERTIFY_* / or auto from RootDSE dnsHostName)" -ForegroundColor DarkGray
    }
}

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

    $auth = [System.DirectoryServices.AuthenticationTypes]::Negotiate

    try {
        if ($DomainController) {
            $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/RootDSE", $null, $null, $auth)
        }
        else {
            $root = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE", $null, $null, $auth)
        }

        return [string]$root.Properties["configurationNamingContext"][0]
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

    $auth = [System.DirectoryServices.AuthenticationTypes]::Negotiate
    $entry = New-Object System.DirectoryServices.DirectoryEntry($LdapPath, $null, $null, $auth)
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
    "Export-DefensiveReport",
    "Resolve-CertifyDefensiveDomainController",
    "Get-CertifyDefensiveDiscoveredDomainControllerDns",
    "Resolve-CertifyDefensiveEnvString",
    "Resolve-CertifyDefensiveEnvInt",
    "Write-CertifyDefensiveExecutionContext"
)
