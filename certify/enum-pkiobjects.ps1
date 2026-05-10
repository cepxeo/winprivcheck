param(
    [string]$DomainController,
    [string]$OutFile
)

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$DomainController = Resolve-CertifyDefensiveDomainController -DomainControllerParameter $DomainController
Write-CertifyDefensiveExecutionContext -DomainController $DomainController

Write-Section "PKI Objects (Defensive Enumeration)"
$configNc = Get-ConfigurationNamingContext -DomainController $DomainController
$basePath = if ($DomainController) { "LDAP://$DomainController/CN=Public Key Services,CN=Services,$configNc" } else { "LDAP://CN=Public Key Services,CN=Services,$configNc" }

$queries = @(
    @{ Name = "Enrollment Services"; Filter = "(objectClass=pKIEnrollmentService)" },
    @{ Name = "Certificate Templates"; Filter = "(objectClass=pKICertificateTemplate)" },
    @{ Name = "OID Objects"; Filter = "(objectClass=msPKI-Enterprise-Oid)" }
)

$report = foreach ($query in $queries) {
    $results = Search-Ldap -LdapPath $basePath -Filter $query.Filter -Properties @("name", "distinguishedName")
    [pscustomobject]@{
        ObjectType = $query.Name
        Count      = $results.Count
        Examples   = @($results | Select-Object -First 5 | ForEach-Object { [string]$_.Properties["name"][0] }) -join ", "
    }
}

$report | Format-Table -AutoSize
Export-DefensiveReport -InputObject $report -OutFile $OutFile
