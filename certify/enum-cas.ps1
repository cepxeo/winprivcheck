param(
    [string]$DomainController,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$DomainController = Resolve-CertifyDefensiveDomainController -DomainControllerParameter $DomainController
Write-CertifyDefensiveExecutionContext -DomainController $DomainController

Write-Section "Enterprise CAs (Defensive Enumeration)"
$configNc = Get-ConfigurationNamingContext -DomainController $DomainController
$ldapPath = if ($DomainController) { "LDAP://$DomainController/CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc" } else { "LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc" }

$results = Search-Ldap -LdapPath $ldapPath -Filter "(objectClass=pKIEnrollmentService)" -Properties @("name", "dnshostname", "cACertificateDN", "certificateTemplates")
$items = foreach ($result in $results) {
    $obj = Convert-SearchResultToObject -Result $result
    [pscustomobject]@{
        Name              = [string]$obj.name
        DnsHostName       = [string]$obj.dnshostname
        CertificateDn     = [string]$obj.cacertificatedn
        PublishedTemplate = @($obj.certificatetemplates)
    }
}

$items | Sort-Object Name | Format-Table -AutoSize
Export-DefensiveReport -InputObject $items -OutFile $OutFile
