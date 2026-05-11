function Invoke-SharpHoundDCOnly {
    <#
    .SYNOPSIS
        Self-contained PowerShell implementation of a SharpHound-style DCOnly LDAP collection.

    .DESCRIPTION
        Collects LDAP-only Active Directory data that maps to SharpHound's DCOnly collection intent:
        Group, Trusts, ObjectProps, ACL, Container, GPOLocalGroup, and configuration/ADCS objects where available.

        This script does not load the SharpHound .NET assembly and does not require the ActiveDirectory module.
        It uses System.DirectoryServices APIs that are available in Windows PowerShell.

    .EXAMPLE
        Invoke-SharpHoundDCOnly -OutputDirectory .\loot -Zip

    .EXAMPLE
        Invoke-SharpHoundDCOnly -Domain corp.example.com -DomainController dc01.corp.example.com -PrettyPrint
    #>

    [CmdletBinding()]
    param(
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $DistinguishedName,

        [String]
        $LdapFilter,

        [Switch]
        $SearchForest,

        [String]
        $LdapUsername,

        [String]
        $LdapPassword,

        [Switch]
        $SecureLDAP,

        [ValidateRange(1, 65535)]
        [Int]
        $LdapPort,

        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [String]
        $OutputDirectory = (Get-Location).Path,

        [String]
        $OutputPrefix,

        [String]
        $ZipFilename,

        [Switch]
        $Zip,

        [Switch]
        $PrettyPrint,

        [Switch]
        $CollectAllProperties,

        [Switch]
        $NoACL,

        [ValidateRange(1, 10000)]
        [Int]
        $PageSize = 1000
    )

    Set-StrictMode -Version 2.0

    Add-Type -AssemblyName System.DirectoryServices
    Add-Type -AssemblyName System.Security

    $script:WriterDepth = 32
    $script:PrettyJson = [Boolean]$PrettyPrint

    function Write-Info {
        param([String]$Message)
        Write-Host "[DCOnly] $Message"
    }

    function ConvertTo-CollectorJson {
        param([Parameter(ValueFromPipeline = $true)]$InputObject)

        process {
            if ($script:PrettyJson) {
                $InputObject | ConvertTo-Json -Depth $script:WriterDepth
            } else {
                $InputObject | ConvertTo-Json -Depth $script:WriterDepth -Compress
            }
        }
    }

    function ConvertTo-DistinguishedName {
        param([String]$DnsName)

        if ([String]::IsNullOrWhiteSpace($DnsName)) {
            return $null
        }

        return (($DnsName -split '\.') | ForEach-Object { "DC=$_" }) -join ','
    }

    function ConvertFrom-DistinguishedName {
        param([String]$DistinguishedName)

        if ([String]::IsNullOrWhiteSpace($DistinguishedName)) {
            return $null
        }

        $parts = @()
        foreach ($part in ($DistinguishedName -split ',')) {
            if ($part -match '^DC=(.+)$') {
                $parts += $Matches[1]
            }
        }

        if ($parts.Count -eq 0) {
            return $null
        }

        return ($parts -join '.').ToUpperInvariant()
    }

    function New-LdapPath {
        param(
            [String]$Server,
            [String]$NamingContext,
            [Switch]$Ssl
        )

        $scheme = if ($Ssl) { 'LDAPS' } else { 'LDAP' }
        $hostPart = ''
        if (-not [String]::IsNullOrWhiteSpace($Server)) {
            $hostPart = $Server
            if ($LdapPort -gt 0) {
                $hostPart = "$hostPart`:$LdapPort"
            }
            $hostPart = "$hostPart/"
        }

        if ([String]::IsNullOrWhiteSpace($NamingContext)) {
            return "$scheme`://$hostPart"
        }

        return "$scheme`://$hostPart$NamingContext"
    }

    function New-DirectoryEntry {
        param(
            [String]$Path,
            [Switch]$UseCredential
        )

        $authType = [System.DirectoryServices.AuthenticationTypes]::Secure
        if ($SecureLDAP) {
            $authType = $authType -bor [System.DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
        }

        if ($UseCredential -and -not [String]::IsNullOrWhiteSpace($LdapUsername)) {
            return New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $Path, $LdapUsername, $LdapPassword, $authType
        }

        return New-Object System.DirectoryServices.DirectoryEntry -ArgumentList $Path
    }

    function Get-RootDse {
        param([String]$Server)

        $path = New-LdapPath -Server $Server -NamingContext 'RootDSE' -Ssl:$SecureLDAP
        $entry = New-DirectoryEntry -Path $path -UseCredential

        $props = @{}
        foreach ($name in $entry.Properties.PropertyNames) {
            $props[$name] = Convert-LdapValue -Value $entry.Properties[$name]
        }

        return $props
    }

    function Convert-LdapValue {
        param($Value)

        if ($null -eq $Value) {
            return $null
        }

        if ($Value -is [System.DirectoryServices.ResultPropertyValueCollection] -or
            $Value -is [System.DirectoryServices.PropertyValueCollection]) {
            $items = @()
            foreach ($item in $Value) {
                $items += Convert-LdapValue -Value $item
            }

            if ($items.Count -eq 0) {
                return $null
            }

            if ($items.Count -eq 1) {
                return $items[0]
            }

            return $items
        }

        if ($Value -is [Byte[]]) {
            return [Convert]::ToBase64String($Value)
        }

        if ($Value -is [System.__ComObject]) {
            try {
                return [String]$Value
            } catch {
                return $null
            }
        }

        if ($Value -is [DateTime]) {
            return $Value.ToUniversalTime().ToString('o')
        }

        return $Value
    }

    function Convert-SidBytes {
        param([Byte[]]$Bytes)

        if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
            return $null
        }

        try {
            return ([System.Security.Principal.SecurityIdentifier]::new($Bytes, 0)).Value.ToUpperInvariant()
        } catch {
            return $null
        }
    }

    function Convert-GuidBytes {
        param([Byte[]]$Bytes)

        if ($null -eq $Bytes -or $Bytes.Length -ne 16) {
            return $null
        }

        try {
            return ([Guid]::new($Bytes)).Guid.ToUpperInvariant()
        } catch {
            return $null
        }
    }

    function Convert-LargeInteger {
        param($Value)

        if ($null -eq $Value) {
            return $null
        }

        try {
            if ($Value -is [Int64] -or $Value -is [Int32]) {
                return [Int64]$Value
            }

            $high = $Value.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
            $low = $Value.GetType().InvokeMember('LowPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
            return ([Int64]$high -shl 32) -bor ([UInt32]$low)
        } catch {
            return $null
        }
    }

    function Convert-FileTime {
        param($Value)

        $ticks = Convert-LargeInteger -Value $Value
        if ($null -eq $ticks -or $ticks -le 0 -or $ticks -eq 9223372036854775807) {
            return $null
        }

        try {
            return [DateTime]::FromFileTimeUtc($ticks).ToString('o')
        } catch {
            return $null
        }
    }

    function Escape-LdapFilterValue {
        param([String]$Value)

        if ($null -eq $Value) {
            return $null
        }

        return $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([String][Char]0, '\00')
    }

    function Get-ResultProperty {
        param(
            [System.DirectoryServices.SearchResult]$Result,
            [String]$Name
        )

        if ($Result.Properties.Contains($Name) -and $Result.Properties[$Name].Count -gt 0) {
            if ($Result.Properties[$Name].Count -eq 1) {
                return $Result.Properties[$Name][0]
            }

            return @($Result.Properties[$Name])
        }

        return $null
    }

    function Get-ResultString {
        param(
            [System.DirectoryServices.SearchResult]$Result,
            [String]$Name
        )

        $value = Get-ResultProperty -Result $Result -Name $Name
        if ($null -eq $value) {
            return $null
        }

        return [String]$value
    }

    function Get-ResultSid {
        param([System.DirectoryServices.SearchResult]$Result)

        $sid = Get-ResultProperty -Result $Result -Name 'objectsid'
        if ($sid -is [Byte[]]) {
            return Convert-SidBytes -Bytes $sid
        }

        return $null
    }

    function Get-ResultGuid {
        param([System.DirectoryServices.SearchResult]$Result)

        $guid = Get-ResultProperty -Result $Result -Name 'objectguid'
        if ($guid -is [Byte[]]) {
            return Convert-GuidBytes -Bytes $guid
        }

        return $null
    }

    function New-LdapSearcher {
        param(
            [String]$Server,
            [String]$SearchBase,
            [String]$Filter,
            [String[]]$Properties,
            [Switch]$IncludeSecurityDescriptor,
            [String]$Name = 'LDAP query'
        )

        $path = New-LdapPath -Server $Server -NamingContext $SearchBase -Ssl:$SecureLDAP
        $entry = New-DirectoryEntry -Path $path -UseCredential
        $searcher = New-Object System.DirectoryServices.DirectorySearcher -ArgumentList $entry
        $searcher.Filter = $Filter
        $searcher.PageSize = $PageSize
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        $searcher.ClientTimeout = New-TimeSpan -Seconds 120
        $searcher.ServerTimeLimit = New-TimeSpan -Seconds 120

        if ($IncludeSecurityDescriptor) {
            $searcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor
                [System.DirectoryServices.SecurityMasks]::Owner -bor
                [System.DirectoryServices.SecurityMasks]::Group
        }

        $searcher.PropertiesToLoad.Clear()
        foreach ($property in $Properties) {
            [void]$searcher.PropertiesToLoad.Add($property)
        }

        return $searcher
    }

    function Invoke-LdapQuery {
        param(
            [String]$Server,
            [String]$SearchBase,
            [String]$Filter,
            [String[]]$Properties,
            [Switch]$IncludeSecurityDescriptor,
            [String]$Name
        )

        $effectiveFilter = $Filter
        if (-not [String]::IsNullOrWhiteSpace($LdapFilter)) {
            $effectiveFilter = "(&$Filter$LdapFilter)"
        }

        Write-Verbose "$Name filter: $effectiveFilter"
        $searcher = New-LdapSearcher -Server $Server -SearchBase $SearchBase -Filter $effectiveFilter -Properties $Properties -IncludeSecurityDescriptor:$IncludeSecurityDescriptor -Name $Name

        try {
            return $searcher.FindAll()
        } catch {
            Write-Warning "$Name failed against ${SearchBase}: $($_.Exception.Message)"
            return @()
        }
    }

    function Get-ObjectClasses {
        param([System.DirectoryServices.SearchResult]$Result)

        $classes = @()
        if ($Result.Properties.Contains('objectclass')) {
            foreach ($class in $Result.Properties['objectclass']) {
                $classes += ([String]$class).ToLowerInvariant()
            }
        }

        return $classes
    }

    function Get-Label {
        param([System.DirectoryServices.SearchResult]$Result)

        $classes = Get-ObjectClasses -Result $Result
        if ($classes -contains 'user' -and -not ($classes -contains 'computer')) { return 'User' }
        if ($classes -contains 'computer') { return 'Computer' }
        if ($classes -contains 'group') { return 'Group' }
        if ($classes -contains 'organizationalunit') { return 'OU' }
        if ($classes -contains 'grouppolicycontainer') { return 'GPO' }
        if ($classes -contains 'domain') { return 'Domain' }
        if ($classes -contains 'certificationauthority') { return 'EnterpriseCA' }
        if ($classes -contains 'pkicertificatetemplate') { return 'CertTemplate' }
        if ($classes -contains 'pkirootca') { return 'RootCA' }
        return 'Container'
    }

    function Convert-ResultToProperties {
        param(
            [System.DirectoryServices.SearchResult]$Result,
            [String]$DomainName,
            [String]$DomainSid
        )

        $props = [Ordered]@{
            domain = $DomainName.ToUpperInvariant()
            name = $null
            distinguishedname = $null
            domainsid = $DomainSid
        }

        foreach ($propertyName in $Result.Properties.PropertyNames) {
            if ($propertyName -in @('ntsecuritydescriptor')) {
                continue
            }

            $props[$propertyName.ToLowerInvariant()] = Convert-LdapValue -Value $Result.Properties[$propertyName]
        }

        $dn = Get-ResultString -Result $Result -Name 'distinguishedname'
        $sam = Get-ResultString -Result $Result -Name 'samaccountname'
        $name = Get-ResultString -Result $Result -Name 'name'
        $dns = Get-ResultString -Result $Result -Name 'dnshostname'

        $props['distinguishedname'] = if ($dn) { $dn.ToUpperInvariant() } else { $null }
        $props['name'] = if ($dns) { $dns.ToUpperInvariant() } elseif ($sam) { "$sam@$DomainName".ToUpperInvariant() } elseif ($name) { "$name@$DomainName".ToUpperInvariant() } else { $dn }

        foreach ($timeProperty in @('lastlogontimestamp', 'lastlogon', 'pwdlastset', 'accountexpires', 'badpasswordtime', 'lastlogoff')) {
            $raw = Get-ResultProperty -Result $Result -Name $timeProperty
            if ($null -ne $raw) {
                $props[$timeProperty] = Convert-FileTime -Value $raw
            }
        }

        $uac = Get-ResultProperty -Result $Result -Name 'useraccountcontrol'
        if ($null -ne $uac) {
            $uacInt = [Int]$uac
            $props['enabled'] = -not (($uacInt -band 0x2) -eq 0x2)
            $props['unconstraineddelegation'] = (($uacInt -band 0x80000) -eq 0x80000)
            $props['trustedtoauth'] = (($uacInt -band 0x1000000) -eq 0x1000000)
            $props['passwordnotreqd'] = (($uacInt -band 0x20) -eq 0x20)
            $props['dontreqpreauth'] = (($uacInt -band 0x400000) -eq 0x400000)
        }

        return $props
    }

    function Convert-SecurityDescriptor {
        param(
            [System.DirectoryServices.SearchResult]$Result,
            [String]$ObjectIdentifier
        )

        $raw = Get-ResultProperty -Result $Result -Name 'ntsecuritydescriptor'
        if (-not ($raw -is [Byte[]])) {
            return @()
        }

        try {
            $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new($raw, 0)
            $aces = @()
            foreach ($ace in $sd.DiscretionaryAcl) {
                $sid = $null
                $objectAceFlags = $null
                $objectAceType = $null
                $inheritedObjectAceType = $null

                try {
                    $sid = $ace.SecurityIdentifier.Value.ToUpperInvariant()
                } catch {
                    $sid = $null
                }

                if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                    $objectAceFlags = $ace.ObjectAceFlags.ToString()
                    if ($ace.ObjectAceType -ne [Guid]::Empty) {
                        $objectAceType = $ace.ObjectAceType.Guid.ToUpperInvariant()
                    }

                    if ($ace.InheritedObjectAceType -ne [Guid]::Empty) {
                        $inheritedObjectAceType = $ace.InheritedObjectAceType.Guid.ToUpperInvariant()
                    }
                }

                $aces += [PSCustomObject][Ordered]@{
                    principalid = $sid
                    rightname = $ace.AceQualifier.ToString()
                    acetype = $ace.AceType.ToString()
                    accessmask = $ace.AccessMask
                    isinherited = $ace.IsInherited
                    objectaceflags = $objectAceFlags
                    objectacetype = $objectAceType
                    inheritedobjectacetype = $inheritedObjectAceType
                    isacl = $true
                    objectid = $ObjectIdentifier
                }
            }

            return $aces
        } catch {
            Write-Verbose "Failed to parse security descriptor for ${ObjectIdentifier}: $($_.Exception.Message)"
            return @()
        }
    }

    function Get-ContainingObject {
        param([String]$DistinguishedName)

        if ([String]::IsNullOrWhiteSpace($DistinguishedName)) {
            return $null
        }

        $parts = $DistinguishedName -split ','
        if ($parts.Count -le 1) {
            return $null
        }

        return ($parts[1..($parts.Count - 1)] -join ',').ToUpperInvariant()
    }

    function Get-CollectorProperties {
        param([Object]$Item)

        if ($null -eq $Item) {
            return $null
        }

        return $Item.PSObject.Properties['Properties'].Value
    }

    function Convert-SearchResult {
        param(
            [System.DirectoryServices.SearchResult]$Result,
            [String]$DomainName,
            [String]$DomainSid,
            [Switch]$IncludeAces
        )

        $sid = Get-ResultSid -Result $Result
        $guid = Get-ResultGuid -Result $Result
        $label = Get-Label -Result $Result
        $dn = Get-ResultString -Result $Result -Name 'distinguishedname'
        $objectId = if ($sid) { $sid } elseif ($guid) { $guid } elseif ($dn) { $dn.ToUpperInvariant() } else { $null }

        $item = [Ordered]@{
            ObjectIdentifier = $objectId
            ObjectType = $label
            Properties = Convert-ResultToProperties -Result $Result -DomainName $DomainName -DomainSid $DomainSid
        }

        if ($label -in @('User', 'Computer', 'Group') -and $sid) {
            $item['DomainSID'] = $DomainSid
        }

        if ($label -eq 'Group') {
            $members = @()
            $memberValues = Get-ResultProperty -Result $Result -Name 'member'
            if ($null -ne $memberValues) {
                foreach ($member in @($memberValues)) {
                    $members += [PSCustomObject][Ordered]@{
                        ObjectIdentifier = ([String]$member).ToUpperInvariant()
                        ObjectType = 'Base'
                    }
                }
            }
            $item['Members'] = $members
        }

        if ($label -eq 'User') {
            $pg = Get-ResultString -Result $Result -Name 'primarygroupid'
            if ($pg -and $sid) {
                $item['PrimaryGroupSID'] = ($sid.Substring(0, $sid.LastIndexOf('-') + 1) + $pg).ToUpperInvariant()
            }
        }

        if ($label -eq 'Computer') {
            $uac = Get-ResultProperty -Result $Result -Name 'useraccountcontrol'
            $item['IsDC'] = (($uac -as [Int]) -band 0x2000) -eq 0x2000
        }

        $containedBy = Get-ContainingObject -DistinguishedName $dn
        if ($containedBy) {
            $item['ContainedBy'] = [PSCustomObject][Ordered]@{
                ObjectIdentifier = $containedBy
                ObjectType = 'Container'
            }
        }

        if ($IncludeAces) {
            $aces = Convert-SecurityDescriptor -Result $Result -ObjectIdentifier $objectId
            $item['Aces'] = $aces
        }

        return [PSCustomObject]$item
    }

    function Write-DataFile {
        param(
            [String]$DataType,
            [Object[]]$Data,
            [String]$Directory
        )

        $prefix = if ([String]::IsNullOrWhiteSpace($OutputPrefix)) { '' } else { "$OutputPrefix`_" }
        $path = Join-Path $Directory "$prefix$DataType.json"
        $payload = [Ordered]@{
            data = @($Data)
            meta = [Ordered]@{
                count = @($Data).Count
                datatype = $DataType
                collectionmethods = @('Group', 'Trusts', 'ObjectProps', 'ACL', 'Container', 'GPOLocalGroup', 'CertServices')
                collectorversion = 'PowerShell-DCOnly-1.0'
                version = 6
            }
        }

        $payload | ConvertTo-CollectorJson | Set-Content -Path $path -Encoding UTF8
        return $path
    }

    function Get-DomainInfo {
        param(
            [String]$Server,
            [String]$DefaultNamingContext
        )

        $results = Invoke-LdapQuery -Server $Server -SearchBase $DefaultNamingContext -Filter '(objectClass=domainDNS)' -Properties @('distinguishedName', 'objectSid', 'name', 'dnsRoot', 'nTSecurityDescriptor', 'objectClass') -IncludeSecurityDescriptor:(-not $NoACL) -Name 'Domain object'
        foreach ($result in $results) {
            $domainSid = Get-ResultSid -Result $result
            $domainName = ConvertFrom-DistinguishedName -DistinguishedName (Get-ResultString -Result $result -Name 'distinguishedname')
            return @{
                Result = $result
                Sid = $domainSid
                Name = $domainName
            }
        }

        return @{
            Result = $null
            Sid = 'UNKNOWN'
            Name = ConvertFrom-DistinguishedName -DistinguishedName $DefaultNamingContext
        }
    }

    function Get-ForestDomains {
        param(
            [String]$Server,
            [String]$ConfigurationNamingContext
        )

        $domains = @()
        $results = Invoke-LdapQuery -Server $Server -SearchBase "CN=Partitions,$ConfigurationNamingContext" -Filter '(&(objectClass=crossRef)(nCName=*)(dnsRoot=*))' -Properties @('dnsRoot', 'nCName') -Name 'Forest domains'
        foreach ($result in $results) {
            $dnsRoot = Get-ResultString -Result $result -Name 'dnsroot'
            $ncName = Get-ResultString -Result $result -Name 'ncname'
            if ($dnsRoot -and $ncName) {
                $domains += [PSCustomObject][Ordered]@{
                    Name = $dnsRoot
                    NamingContext = $ncName
                }
            }
        }

        return $domains
    }

    function Get-GPOLocalGroupHints {
        param(
            [Object[]]$Gpos,
            [String]$DomainName
        )

        $items = @()
        foreach ($gpo in $Gpos) {
            $props = Get-CollectorProperties -Item $gpo
            if ($null -eq $props) {
                continue
            }

            $gpcPath = $props['gpcfilesyspath']
            if ([String]::IsNullOrWhiteSpace($gpcPath)) {
                continue
            }

            foreach ($relativePath in @('MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf', 'MACHINE\Preferences\Groups\Groups.xml')) {
                $path = Join-Path $gpcPath $relativePath
                if (-not (Test-Path -LiteralPath $path)) {
                    continue
                }

                $items += [PSCustomObject][Ordered]@{
                    ObjectIdentifier = $gpo.ObjectIdentifier
                    ObjectType = 'GPOLocalGroup'
                    Properties = [Ordered]@{
                        domain = $DomainName.ToUpperInvariant()
                        name = $props['name']
                        gpcfilesyspath = $gpcPath
                        policyfile = $path
                    }
                }
            }
        }

        return $items
    }

    $root = Get-RootDse -Server $DomainController
    $defaultNC = if ($DistinguishedName) { $DistinguishedName } else { [String]$root['defaultNamingContext'] }
    $configNC = [String]$root['configurationNamingContext']
    $currentDomain = if ($Domain) { $Domain } else { ConvertFrom-DistinguishedName -DistinguishedName $defaultNC }

    if ([String]::IsNullOrWhiteSpace($defaultNC)) {
        throw 'Unable to determine defaultNamingContext. Specify -DomainController and/or -DistinguishedName.'
    }

    $domainTargets = @([PSCustomObject][Ordered]@{
        Name = $currentDomain
        NamingContext = $defaultNC
    })

    if ($SearchForest -and -not [String]::IsNullOrWhiteSpace($configNC)) {
        $forestDomains = Get-ForestDomains -Server $DomainController -ConfigurationNamingContext $configNC
        if (@($forestDomains).Count -gt 0) {
            $domainTargets = $forestDomains
        }
    }

    $defaultProperties = @(
        'objectClass', 'objectSid', 'objectGuid', 'distinguishedName', 'name', 'cn', 'sAMAccountName',
        'member', 'memberOf', 'primaryGroupID', 'userAccountControl', 'servicePrincipalName',
        'adminCount', 'pwdLastSet', 'lastLogonTimestamp', 'lastLogon', 'whenCreated', 'whenChanged',
        'displayName', 'description', 'mail', 'title', 'department', 'company', 'manager',
        'dnsHostName', 'operatingSystem', 'operatingSystemVersion', 'msDS-AllowedToDelegateTo',
        'msDS-AllowedToActOnBehalfOfOtherIdentity', 'sIDHistory', 'gPLink', 'gPOptions',
        'gPCFileSysPath', 'flags', 'trustDirection', 'trustType', 'trustAttributes',
        'nTSecurityDescriptor'
    )

    if ($CollectAllProperties) {
        $defaultProperties = @('*', 'nTSecurityDescriptor')
    }

    $configProperties = @(
        'objectClass', 'objectSid', 'objectGuid', 'distinguishedName', 'name', 'cn', 'displayName',
        'certificateTemplates', 'cACertificateDN', 'dNSHostName', 'flags', 'pKIExpirationPeriod',
        'pKIOverlapPeriod', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag',
        'msPKI-Private-Key-Flag', 'msPKI-RA-Signature', 'msPKI-Certificate-Application-Policy',
        'msPKI-RA-Application-Policies', 'nTSecurityDescriptor'
    )

    $users = @()
    $computers = @()
    $groups = @()
    $domains = @()
    $ous = @()
    $gpos = @()
    $containers = @()
    $trusts = @()
    $acls = @()
    $certServices = @()

    foreach ($target in $domainTargets) {
        Write-Info "Collecting $($target.Name) from $($target.NamingContext)"
        $domainInfo = Get-DomainInfo -Server $DomainController -DefaultNamingContext $target.NamingContext
        $domainName = if ($domainInfo['Name']) { [String]$domainInfo['Name'] } else { [String]$target.Name }
        $domainSid = if ($domainInfo['Sid']) { [String]$domainInfo['Sid'] } else { 'UNKNOWN' }

        if ($domainInfo['Result']) {
            $domainObject = Convert-SearchResult -Result $domainInfo['Result'] -DomainName $domainName -DomainSid $domainSid -IncludeAces:(-not $NoACL)
            (Get-CollectorProperties -Item $domainObject)['collected'] = $true
            $domains += $domainObject
            if (-not $NoACL) {
                $acls += @($domainObject.Aces)
            }
        }

        $mainFilter = '(|(&(objectCategory=person)(objectClass=user))(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit)(objectClass=container)(objectClass=groupPolicyContainer)(objectClass=trustedDomain))'
        $results = Invoke-LdapQuery -Server $DomainController -SearchBase $target.NamingContext -Filter $mainFilter -Properties $defaultProperties -IncludeSecurityDescriptor:(-not $NoACL) -Name 'DCOnly default naming context'

        foreach ($result in $results) {
            $item = Convert-SearchResult -Result $result -DomainName $domainName -DomainSid $domainSid -IncludeAces:(-not $NoACL)
            if (-not $NoACL) {
                $acls += @($item.Aces)
            }

            switch ($item.ObjectType) {
                'User' { $users += $item }
                'Computer' { $computers += $item }
                'Group' { $groups += $item }
                'OU' { $ous += $item }
                'GPO' { $gpos += $item }
                default {
                    $classes = Get-ObjectClasses -Result $result
                    if ($classes -contains 'trusteddomain') {
                        $trusts += $item
                    } else {
                        $containers += $item
                    }
                }
            }
        }

        $gpoHints = Get-GPOLocalGroupHints -Gpos $gpos -DomainName $domainName
        if (@($gpoHints).Count -gt 0) {
            $containers += $gpoHints
        }
    }

    if (-not [String]::IsNullOrWhiteSpace($configNC)) {
        Write-Info "Collecting configuration naming context $configNC"
        $configFilter = '(|(objectClass=certificationAuthority)(objectClass=pKIEnrollmentService)(objectClass=pKICertificateTemplate)(objectClass=pKIEnterpriseOid)(objectClass=pKIView)(objectClass=cRLDistributionPoint)(objectClass=container))'
        $configResults = Invoke-LdapQuery -Server $DomainController -SearchBase $configNC -Filter $configFilter -Properties $configProperties -IncludeSecurityDescriptor:(-not $NoACL) -Name 'DCOnly configuration naming context'

        $configDomain = if ($currentDomain) { $currentDomain } else { 'CONFIGURATION' }
        foreach ($result in $configResults) {
            $item = Convert-SearchResult -Result $result -DomainName $configDomain -DomainSid 'CONFIGURATION' -IncludeAces:(-not $NoACL)
            if (-not $NoACL) {
                $acls += @($item.Aces)
            }

            $classes = Get-ObjectClasses -Result $result
            if (($classes -contains 'certificationauthority') -or
                ($classes -contains 'pkienrollmentservice') -or
                ($classes -contains 'pkicertificatetemplate') -or
                ($classes -contains 'pkienterpriseoid')) {
                $certServices += $item
            } else {
                $containers += $item
            }
        }
    }

    $written = @()
    $written += Write-DataFile -DataType 'users' -Data $users -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'computers' -Data $computers -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'groups' -Data $groups -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'domains' -Data $domains -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'ous' -Data $ous -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'gpos' -Data $gpos -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'containers' -Data $containers -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'trusts' -Data $trusts -Directory $OutputDirectory
    $written += Write-DataFile -DataType 'certservices' -Data $certServices -Directory $OutputDirectory
    if (-not $NoACL) {
        $written += Write-DataFile -DataType 'acls' -Data $acls -Directory $OutputDirectory
    }

    if ($Zip) {
        if ([String]::IsNullOrWhiteSpace($ZipFilename)) {
            $stamp = Get-Date -Format 'yyyyMMddHHmmss'
            $zipBase = if ([String]::IsNullOrWhiteSpace($OutputPrefix)) { "SharpHoundDCOnly_$stamp.zip" } else { "$OutputPrefix`_SharpHoundDCOnly_$stamp.zip" }
            $ZipFilename = Join-Path $OutputDirectory $zipBase
        }

        if (Test-Path -LiteralPath $ZipFilename) {
            Remove-Item -LiteralPath $ZipFilename -Force
        }

        Compress-Archive -Path $written -DestinationPath $ZipFilename -Force
        Write-Info "Wrote $ZipFilename"
    }

    Write-Info "Wrote $(@($written).Count) JSON files to $OutputDirectory"
    return $written
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-SharpHoundDCOnly @PSBoundParameters
}
