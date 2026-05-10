[CmdletBinding()]
param(
    [string]$Domain,

    [Alias('DomainController', 'Server')]
    [string]$LdapServer,

    [switch]$ShowLinkedOids,
    [switch]$ShowAdmins,

    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-LdapConfigurationPath {
    param([string]$TargetDomain)

    $rootDsePath = if ([string]::IsNullOrWhiteSpace($TargetDomain)) { 'LDAP://RootDSE' } else { "LDAP://$TargetDomain/RootDSE" }
    $root = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $rootDsePath
    return [string]$root.Properties['configurationNamingContext'][0]
}

function Join-LdapPath {
    param(
        [string]$Server,
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($Server)) {
        return "LDAP://$DistinguishedName"
    }

    return "LDAP://$Server/$DistinguishedName"
}

function Search-LdapObjects {
    param(
        [string]$LdapPath,
        [string]$Filter = '(objectClass=*)',
        [string[]]$Properties = @()
    )

    $root = New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $LdapPath
    $searcher = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $root
    $searcher.Filter = $Filter
    $searcher.PageSize = 500
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner

    foreach ($property in $Properties) {
        [void]$searcher.PropertiesToLoad.Add($property)
    }

    return $searcher.FindAll()
}

function Search-DefaultNamingContext {
    param(
        [string]$Filter,
        [string[]]$Properties = @()
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = $Filter
    $searcher.PageSize = 500
    $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Owner

    foreach ($property in $Properties) {
        [void]$searcher.PropertiesToLoad.Add($property)
    }

    return $searcher.FindAll()
}

function Get-SearchValue {
    param(
        [System.DirectoryServices.SearchResult]$SearchResult,
        [string]$Name
    )

    if ($SearchResult.Properties.Contains($Name) -and $SearchResult.Properties[$Name].Count -gt 0) {
        return $SearchResult.Properties[$Name][0]
    }

    return $null
}

function Get-SearchValues {
    param(
        [System.DirectoryServices.SearchResult]$SearchResult,
        [string]$Name
    )

    if ($SearchResult.Properties.Contains($Name)) {
        return @($SearchResult.Properties[$Name] | ForEach-Object { [string]$_ })
    }

    return $null
}

function Get-DomainNameFromDn {
    param([string]$DistinguishedName)

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return $null
    }

    $idx = $DistinguishedName.IndexOf('DC=')
    if ($idx -eq -1) {
        return $null
    }

    return $DistinguishedName.Substring($idx + 3).Replace(',DC=', '.')
}

function Get-SecurityDescriptor {
    param([System.DirectoryServices.SearchResult]$SearchResult)

    $raw = Get-SearchValue -SearchResult $SearchResult -Name 'ntsecuritydescriptor'
    if ($null -eq $raw) {
        return $null
    }

    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
    $sd.SetSecurityDescriptorBinaryForm([byte[]]$raw)
    return $sd
}

function Test-IsAdminSid {
    param([string]$Sid)

    return ($Sid -match '^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$') -or
        $Sid -eq 'S-1-5-9' -or
        $Sid -eq 'S-1-5-32-544'
}

function Get-UserNameFromSid {
    param([string]$Sid)

    try {
        return (New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $Sid).Translate([System.Security.Principal.NTAccount]).ToString()
    }
    catch {
        return '<UNKNOWN>'
    }
}

function Get-UserSidString {
    param(
        [string]$Sid,
        [int]$Padding = 35
    )

    return (Get-UserNameFromSid -Sid $Sid).PadRight($Padding) + $Sid
}

function New-PkiObject {
    param(
        [System.DirectoryServices.SearchResult]$SearchResult,
        [string]$NameProperty = 'name'
    )

    $dn = [string](Get-SearchValue -SearchResult $SearchResult -Name 'distinguishedname')

    return [pscustomobject]@{
        DistinguishedName  = $dn
        Name               = [string](Get-SearchValue -SearchResult $SearchResult -Name $NameProperty)
        DomainName         = Get-DomainNameFromDn -DistinguishedName $dn
        SecurityDescriptor = Get-SecurityDescriptor -SearchResult $SearchResult
    }
}

function Get-EnterpriseCAs {
    param(
        [string]$ConfigurationPath,
        [string]$Server
    )

    $ldapPath = Join-LdapPath -Server $Server -DistinguishedName "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigurationPath"
    $results = Search-LdapObjects -LdapPath $ldapPath -Filter '(objectCategory=pKIEnrollmentService)' -Properties @('name', 'dnshostname', 'distinguishedName', 'nTSecurityDescriptor')

    foreach ($result in $results) {
        [pscustomobject]@{
            Name               = [string](Get-SearchValue -SearchResult $result -Name 'name')
            DnsHostname        = [string](Get-SearchValue -SearchResult $result -Name 'dnshostname')
            DistinguishedName  = [string](Get-SearchValue -SearchResult $result -Name 'distinguishedname')
            SecurityDescriptor = Get-SecurityDescriptor -SearchResult $result
        }
    }
}

function Get-PkiObjects {
    param(
        [string]$ConfigurationPath,
        [string]$Server
    )

    $objects = New-Object System.Collections.Generic.List[object]
    $publicKeyServicesPath = Join-LdapPath -Server $Server -DistinguishedName "CN=Public Key Services,CN=Services,$ConfigurationPath"
    $pkiResults = Search-LdapObjects -LdapPath $publicKeyServicesPath -Properties @('name', 'distinguishedName', 'nTSecurityDescriptor')

    foreach ($result in $pkiResults) {
        [void]$objects.Add((New-PkiObject -SearchResult $result -NameProperty 'name'))
    }

    $caDnsFilters = New-Object System.Collections.Generic.List[string]
    foreach ($ca in @(Get-EnterpriseCAs -ConfigurationPath $ConfigurationPath -Server $Server)) {
        if (-not [string]::IsNullOrWhiteSpace($ca.DnsHostname)) {
            [void]$caDnsFilters.Add("(dnshostname=$($ca.DnsHostname))")
        }
    }

    if ($caDnsFilters.Count -gt 0) {
        $caNameFilter = "(|$($caDnsFilters.ToArray() -join ''))"
        $caHostResults = Search-DefaultNamingContext -Filter $caNameFilter -Properties @('samaccountname', 'distinguishedName', 'nTSecurityDescriptor')

        foreach ($result in $caHostResults) {
            [void]$objects.Add((New-PkiObject -SearchResult $result -NameProperty 'samaccountname'))
        }
    }

    return @($objects.ToArray())
}

function Add-ControllerEntry {
    param(
        [hashtable]$Controllers,
        [string]$Sid,
        [string]$Right,
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return
    }

    if (-not $Controllers.ContainsKey($Sid)) {
        $Controllers[$Sid] = New-Object System.Collections.Generic.List[object]
    }

    [void]$Controllers[$Sid].Add([pscustomobject]@{
        Right             = $Right
        DistinguishedName = $DistinguishedName
    })
}

function Get-PkiObjectControllers {
    param([object[]]$PkiObjects)

    $controllers = @{}

    foreach ($pkiObject in $PkiObjects) {
        if ($null -eq $pkiObject.SecurityDescriptor) {
            continue
        }

        $ownerSid = $pkiObject.SecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).ToString()
        Add-ControllerEntry -Controllers $controllers -Sid $ownerSid -Right 'Owner' -DistinguishedName $pkiObject.DistinguishedName

        foreach ($ace in $pkiObject.SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $principalSid = $ace.IdentityReference.ToString()
            $rights = $ace.ActiveDirectoryRights
            $objectType = $ace.ObjectType.ToString()

            if ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
                Add-ControllerEntry -Controllers $controllers -Sid $principalSid -Right 'GenericAll' -DistinguishedName $pkiObject.DistinguishedName
            }
            elseif ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) {
                Add-ControllerEntry -Controllers $controllers -Sid $principalSid -Right 'WriteOwner' -DistinguishedName $pkiObject.DistinguishedName
            }
            elseif ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) {
                Add-ControllerEntry -Controllers $controllers -Sid $principalSid -Right 'WriteDacl' -DistinguishedName $pkiObject.DistinguishedName
            }
            elseif ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and $objectType -eq '00000000-0000-0000-0000-000000000000') {
                Add-ControllerEntry -Controllers $controllers -Sid $principalSid -Right 'WriteAllProperties' -DistinguishedName $pkiObject.DistinguishedName
            }
        }
    }

    return $controllers
}

function Write-PkiObjectControllers {
    param(
        [hashtable]$Controllers,
        [bool]$HideAdmins
    )

    foreach ($entry in @($Controllers.GetEnumerator() | Sort-Object { Get-UserNameFromSid -Sid $_.Key })) {
        if ($entry.Value.Count -eq 0) {
            continue
        }

        $sid = $entry.Key
        if ($HideAdmins -and ((Test-IsAdminSid -Sid $sid) -or $sid -eq 'S-1-5-18')) {
            continue
        }

        $name = Get-UserNameFromSid -Sid $sid
        Write-Host ''

        if ([string]::IsNullOrEmpty($name)) {
            Write-Host "    $sid"
        }
        else {
            Write-Host "    $name ($sid)"
        }

        foreach ($controller in $entry.Value) {
            Write-Host ("        {0,-18} {1}" -f $controller.Right, $controller.DistinguishedName)
        }
    }
}

function Get-EnterpriseOids {
    param(
        [string]$ConfigurationPath,
        [string]$Server
    )

    $ldapPath = Join-LdapPath -Server $Server -DistinguishedName "CN=OID,CN=Public Key Services,CN=Services,$ConfigurationPath"
    $results = Search-LdapObjects -LdapPath $ldapPath -Filter '(objectClass=msPKI-Enterprise-Oid)' -Properties @('displayName', 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink')

    foreach ($result in $results) {
        $groupLink = [string](Get-SearchValue -SearchResult $result -Name 'msds-oidtogrouplink')
        if ([string]::IsNullOrWhiteSpace($groupLink)) {
            continue
        }

        [pscustomobject]@{
            Oid         = [string](Get-SearchValue -SearchResult $result -Name 'mspki-cert-template-oid')
            DisplayName = [string](Get-SearchValue -SearchResult $result -Name 'displayname')
            GroupLink   = $groupLink
        }
    }
}

function Export-ConsoleOutput {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        & $ScriptBlock
        return
    }

    $dir = Split-Path -Path $Path -Parent
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    & $ScriptBlock *> $Path
}

function Invoke-EnumPkiObjects {
    Write-Host '[*] Action: Find PKI object controllers'

    if (-not [string]::IsNullOrWhiteSpace($Domain) -and $Domain -notmatch '\.') {
        Write-Host "[X] The 'domain' parameter is not a fully qualified domain name."
        return
    }

    $configurationPath = Get-LdapConfigurationPath -TargetDomain $Domain
    Write-Host "[*] Using the search base '$configurationPath'"

    $pkiObjects = @(Get-PkiObjects -ConfigurationPath $configurationPath -Server $LdapServer)
    $objectControllers = Get-PkiObjectControllers -PkiObjects $pkiObjects

    Write-Host ''
    Write-Host '[*] PKI Object Controllers:'
    Write-PkiObjectControllers -Controllers $objectControllers -HideAdmins (-not $ShowAdmins.IsPresent)

    if ($ShowLinkedOids) {
        $oids = @(Get-EnterpriseOids -ConfigurationPath $configurationPath -Server $LdapServer)

        if ($oids.Count -eq 0) {
            Write-Host '[*] There are no group-linked enterprise OIDs.'
        }
        else {
            Write-Host ''
            Write-Host '[*] Group-linked Enterprise OIDs:'

            foreach ($oid in $oids) {
                Write-Host ''
                Write-Host "Oid          :  $($oid.Oid)"
                Write-Host "Display Name :  $($oid.DisplayName)"
                Write-Host "Linked Group :  $($oid.GroupLink)"
            }
        }
    }
}

Export-ConsoleOutput -Path $OutFile -ScriptBlock {
    Invoke-EnumPkiObjects
}
