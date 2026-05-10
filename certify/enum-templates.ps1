param(
    [string]$DomainController,
    [switch]$FilterEnabled,
    [switch]$FilterVulnerable,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

Write-Section "Certificate Templates (Defensive Enumeration)"
$configNc = Get-ConfigurationNamingContext -DomainController $DomainController
$ldapPath = if ($DomainController) { "LDAP://$DomainController/CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc" } else { "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNc" }

$results = Search-Ldap -LdapPath $ldapPath -Filter "(objectClass=pKICertificateTemplate)" -Properties @("name", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "pKIExtendedKeyUsage", "flags")

$items = foreach ($result in $results) {
    $obj = Convert-SearchResultToObject -Result $result
    $risk = Test-TemplateRisk -Template $obj
    $flagsRaw = 0
    if ($obj.flags) {
        [void][int]::TryParse([string]$obj.flags, [ref]$flagsRaw)
    }
    [pscustomobject]@{
        Name            = $risk.TemplateName
        DisplayName     = $risk.DisplayName
        Enabled         = (($flagsRaw -band 16) -eq 0)
        RiskCount       = $risk.RiskCount
        RiskFlags       = $risk.RiskFlags -join "; "
        NameFlagRaw     = [string]$obj.'mspki-certificate-name-flag'
        EnrollmentFlags = [string]$obj.'mspki-enrollment-flag'
        Eku             = @($obj.'pkiextendedkeyusage') -join ", "
    }
}

if ($FilterEnabled) {
    $items = $items | Where-Object { $_.Enabled }
}

if ($FilterVulnerable) {
    $items = $items | Where-Object { $_.RiskCount -gt 0 }
}

$items | Sort-Object RiskCount -Descending, Name | Format-Table -AutoSize
Export-DefensiveReport -InputObject $items -OutFile $OutFile
