[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Alias('CA')]
    [string]$CAName,

    [string]$Domain,

    [Alias('DomainController', 'Server')]
    [string]$LdapServer,

    [Parameter(ParameterSetName = 'MarkCurrentUser')]
    [switch]$CurrentUser,

    [Parameter(ParameterSetName = 'MarkTargetUser')]
    [string]$TargetUser,

    [switch]$FilterVulnerable,
    [switch]$HideAdmins,
    [switch]$ShowAllPermissions,
    [switch]$SkipWebServiceChecks,

    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:CommonOids = @{
    NtdsCaSecurityExt = '1.3.6.1.4.1.311.25.2'
}

$script:CaFlags = [ordered]@{
    0x00000001 = 'NO_TEMPLATE_SUPPORT'
    0x00000002 = 'SUPPORTS_NT_AUTHENTICATION'
    0x00000004 = 'CA_SUPPORTS_MANUAL_AUTHENTICATION'
    0x00000008 = 'CA_SERVERTYPE_ADVANCED'
}

$script:EditFlags = @{
    ATTRIBUTE_SUBJECTALTNAME2 = [uint32]0x00040000
}

$script:InterfaceFlags = @{
    NO_REMOTE_ICERTREQUEST       = [uint32]0x00000002
    NO_LOCAL_ICERTREQUEST        = [uint32]0x00000004
    NO_RPC_ICERTREQUEST          = [uint32]0x00000008
    ENFORCE_ENCRYPT_ICERTREQUEST = [uint32]0x00000200
}

$script:CaRights = [ordered]@{
    1   = 'ManageCA'
    2   = 'ManageCertificates'
    4   = 'Auditor'
    8   = 'Operator'
    256 = 'Read'
    512 = 'Enroll'
}

function Test-Flag {
    param(
        [uint32]$Value,
        [uint32]$Flag
    )

    return (($Value -band $Flag) -eq $Flag)
}

function ConvertTo-FlagString {
    param(
        [uint32]$Value,
        $Map
    )

    $names = foreach ($entry in $Map.GetEnumerator()) {
        $flag = [uint32]$entry.Key
        if (Test-Flag -Value $Value -Flag $flag) {
            [string]$entry.Value
        }
    }

    if (@($names).Count -eq 0) {
        return 'NONE'
    }

    return (@($names) -join ', ')
}

function ConvertTo-UInt32 {
    param($Value)

    if ($null -eq $Value) {
        return [uint32]0
    }

    [uint32]$result = 0
    if ([uint32]::TryParse([string]$Value, [ref]$result)) {
        return $result
    }

    [int]$signed = 0
    if ([int]::TryParse([string]$Value, [ref]$signed)) {
        return [BitConverter]::ToUInt32([BitConverter]::GetBytes($signed), 0)
    }

    return [uint32]0
}

function Get-FlagState {
    param(
        [uint32]$Flags,
        [uint32]$Flag
    )

    if (Test-Flag -Value $Flags -Flag $Flag) {
        return 'Enabled'
    }

    return 'Disabled'
}

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
        [string]$Filter,
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
        return @($SearchResult.Properties[$Name] | ForEach-Object { $_ })
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

function Get-SearchGuid {
    param([System.DirectoryServices.SearchResult]$SearchResult)

    $raw = Get-SearchValue -SearchResult $SearchResult -Name 'objectguid'
    if ($null -eq $raw) {
        return [Guid]::Empty
    }

    return [Guid]([byte[]]$raw)
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

function Get-Certificates {
    param([System.DirectoryServices.SearchResult]$SearchResult)

    if (-not $SearchResult.Properties.Contains('cacertificate')) {
        return $null
    }

    $values = $SearchResult.Properties['cacertificate']
    $dn = [string](Get-SearchValue -SearchResult $SearchResult -Name 'distinguishedname')
    for ($i = 0; $i -lt $values.Count; $i++) {
        $raw = $values[$i]
        if ($null -ne $raw) {
            try {
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,[byte[]]$raw)
            }
            catch {
                $index = $i + 1
                Write-Host "[!] Warning: Unable to parse cACertificate value #$index for '$dn': $($_.Exception.Message)"
            }
        }
    }
}

function Test-IsAdminSid {
    param([string]$Sid)

    return ($Sid -match '^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$') -or
        $Sid -eq 'S-1-5-9' -or
        $Sid -eq 'S-1-5-32-544'
}

function Test-IsLowPrivSid {
    param([string]$Sid)

    return ($Sid -match '^S-1-5-21-.+-(513|515|545)$') -or
        $Sid -eq 'S-1-1-0' -or
        $Sid -eq 'S-1-5-11'
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

function Get-CurrentUserSids {
    try {
        $self = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        Write-Host "[*] Classifying vulnerabilities in the context of the current user ('$($self.Name)') and its unrolled groups."

        $sids = New-Object System.Collections.Generic.List[string]
        foreach ($group in $self.Groups) {
            [void]$sids.Add($group.ToString())
        }

        [void]$sids.Add($self.User.ToString())
        return @($sids.ToArray())
    }
    catch {
        throw "Unable to resolve the current Windows identity and groups. $($_.Exception.Message)"
    }
}

function Get-TargetUserSids {
    param(
        [string]$Identity,
        [string]$TargetDomain
    )

    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    $context = if ([string]::IsNullOrWhiteSpace($TargetDomain)) {
        New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
    }
    else {
        New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, $TargetDomain)
    }

    $user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context, $Identity)

    if ($null -eq $user) {
        if ([string]::IsNullOrWhiteSpace($TargetDomain)) {
            Write-Host "[!] Could not find user '$Identity' in current domain."
        }
        else {
            Write-Host "[!] Could not find user '$Identity' in domain '$TargetDomain'."
        }

        return $null
    }

    $userIdentity = New-Object System.Security.Principal.WindowsIdentity -ArgumentList $user.UserPrincipalName
    Write-Host "[*] Classifying vulnerabilities in the context of the target user ('$($userIdentity.Name)') and its unrolled groups."

    $sids = New-Object System.Collections.Generic.List[string]
    foreach ($group in $userIdentity.Groups) {
        [void]$sids.Add($group.ToString())
    }

    [void]$sids.Add($userIdentity.User.ToString())
    return @($sids.ToArray())
}

function Get-RemoteRegistryValue {
    param(
        [string]$ComputerName,
        [string]$KeyName,
        [string]$ValueName
    )

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {
        throw 'DnsHostname is null'
    }

    $baseKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $ComputerName)
    $subKey = $baseKey.OpenSubKey($KeyName)

    if ($null -eq $subKey) {
        return $null
    }

    return $subKey.GetValue($ValueName)
}

function Test-UrlExists {
    param(
        [string]$Url,
        [string]$AuthType = 'Negotiate'
    )

    $response = $null
    try {
        $request = [System.Net.WebRequest]::CreateHttp($Url)
        $request.Timeout = 3000
        $request.Credentials = New-Object System.Net.CredentialCache
        $request.Credentials.Add([Uri]$Url, $AuthType, [System.Net.CredentialCache]::DefaultNetworkCredentials)
        $request.ServerCertificateValidationCallback = { $true }
        $response = [System.Net.HttpWebResponse]$request.GetResponse()
        return @([System.Net.HttpStatusCode]::OK, [System.Net.HttpStatusCode]::Unauthorized, [System.Net.HttpStatusCode]::Forbidden) -contains $response.StatusCode
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $response) {
            $response.Dispose()
        }
    }
}

function Get-CaWebServices {
    param([pscustomobject]$CA)

    $webServices = [pscustomobject]@{
        LegacyAspEnrollmentUrls          = New-Object System.Collections.Generic.List[string]
        EnrollmentWebServiceUrls         = New-Object System.Collections.Generic.List[string]
        EnrollmentPolicyWebServiceUrls   = New-Object System.Collections.Generic.List[string]
        NetworkDeviceEnrollmentServiceUrls = New-Object System.Collections.Generic.List[string]
    }

    if ([string]::IsNullOrWhiteSpace($CA.DnsHostname)) {
        throw 'DnsHostname is null'
    }

    foreach ($protocol in @('http://', 'https://')) {
        $legacyUrl = "$protocol$($CA.DnsHostname)/certsrv/"
        if (Test-UrlExists -Url $legacyUrl -AuthType 'NTLM') {
            [void]$webServices.LegacyAspEnrollmentUrls.Add($legacyUrl)
        }

        $enrollmentUrl = "$protocol$($CA.DnsHostname)/$($CA.Name)_CES_Kerberos/service.svc"
        if (Test-UrlExists -Url $enrollmentUrl) {
            [void]$webServices.EnrollmentWebServiceUrls.Add($enrollmentUrl)
        }

        $policyUrl = "$protocol$($CA.DnsHostname)/ADPolicyProvider_CEP_Kerberos/service.svc"
        if (Test-UrlExists -Url $policyUrl) {
            [void]$webServices.EnrollmentPolicyWebServiceUrls.Add($policyUrl)
        }

        $ndesUrl = "$protocol$($CA.DnsHostname)/certsrv/mscep/"
        if (Test-UrlExists -Url $ndesUrl) {
            [void]$webServices.NetworkDeviceEnrollmentServiceUrls.Add($ndesUrl)
        }
    }

    return $webServices
}

function Update-CaRuntimeInfo {
    param(
        [pscustomobject]$CA,
        [string[]]$UserSids
    )

    try {
        $editFlags = ConvertTo-UInt32 (Get-RemoteRegistryValue -ComputerName $CA.DnsHostname -KeyName "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CA.Name)\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy" -ValueName 'EditFlags')
        $CA.UserSpecifiedSan = Get-FlagState -Flags $editFlags -Flag $script:EditFlags.ATTRIBUTE_SUBJECTALTNAME2
    }
    catch {
        Write-Host "[X] Could not connect to the HKLM hive - $($_.Exception.Message)"
        $CA.UserSpecifiedSan = $_.Exception.Message
    }

    try {
        $interfaceFlags = ConvertTo-UInt32 (Get-RemoteRegistryValue -ComputerName $CA.DnsHostname -KeyName "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CA.Name)" -ValueName 'InterfaceFlags')
        $CA.RpcRequestEncryption = Get-FlagState -Flags $interfaceFlags -Flag $script:InterfaceFlags.ENFORCE_ENCRYPT_ICERTREQUEST

        $restrictions = New-Object System.Collections.Generic.List[string]
        if (Test-Flag -Value $interfaceFlags -Flag $script:InterfaceFlags.NO_REMOTE_ICERTREQUEST) { [void]$restrictions.Add('No Remote') }
        if (Test-Flag -Value $interfaceFlags -Flag $script:InterfaceFlags.NO_LOCAL_ICERTREQUEST) { [void]$restrictions.Add('No Local') }
        if (Test-Flag -Value $interfaceFlags -Flag $script:InterfaceFlags.NO_RPC_ICERTREQUEST) { [void]$restrictions.Add('No Access') }
        $CA.RpcRequestRestrictions = @($restrictions.ToArray())
    }
    catch {
        Write-Host "[X] Could not connect to the HKLM hive - $($_.Exception.Message)"
        $CA.RpcRequestEncryption = $_.Exception.Message
    }

    try {
        $disabledExtensions = Get-RemoteRegistryValue -ComputerName $CA.DnsHostname -KeyName "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CA.Name)\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy" -ValueName 'DisableExtensionList'
        $CA.DisabledExtensions = @($disabledExtensions | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }
    catch {
        $CA.DisabledExtensions = @()
    }

    try {
        $security = Get-RemoteRegistryValue -ComputerName $CA.DnsHostname -KeyName "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CA.Name)" -ValueName 'Security'
        if ($null -ne $security) {
            $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $sd.SetSecurityDescriptorBinaryForm([byte[]]$security, [System.Security.AccessControl.AccessControlSections]::All)
            $CA.ServerSecurityDescriptor = $sd
        }
    }
    catch {
        Write-Host "[X] Could not connect to the HKLM hive - $($_.Exception.Message)"
        $CA.ServerSecurityDescriptor = $null
    }

    try {
        $eaSecurity = Get-RemoteRegistryValue -ComputerName $CA.DnsHostname -KeyName "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CA.Name)" -ValueName 'EnrollmentAgentRights'
        if ($null -ne $eaSecurity) {
            $CA.EnrollmentAgentSecurity = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ([byte[]]$eaSecurity, 0)
        }
    }
    catch {
        $CA.EnrollmentAgentSecurity = $null
    }

    $vulnerabilities = [ordered]@{}
    if ($CA.UserSpecifiedSan -eq 'Enabled') {
        $vulnerabilities[6] = 'The CA allows enrollees to specify SANs.'
    }

    if ($null -ne $CA.ServerSecurityDescriptor) {
        $ownerSid = $CA.ServerSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $esc7 = (($null -eq $UserSids -and (Test-IsLowPrivSid -Sid $ownerSid)) -or ($null -ne $UserSids -and $UserSids -contains $ownerSid))

        foreach ($ace in $CA.ServerSecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $rightsValue = [uint32]$ace.ActiveDirectoryRights
            $sid = $ace.IdentityReference.Value
            $matchesScope = (($null -eq $UserSids -and (Test-IsLowPrivSid -Sid $sid)) -or ($null -ne $UserSids -and $UserSids -contains $sid))

            if ($matchesScope -and ((Test-Flag -Value $rightsValue -Flag 1) -or (Test-Flag -Value $rightsValue -Flag 2))) {
                $esc7 = $true
            }
        }

        if ($esc7) {
            $vulnerabilities[7] = 'The CA has insecure delegated security roles or permissions.'
        }
    }

    $httpUrl = "http://$($CA.DnsHostname)/certsrv/"
    $httpsUrl = "https://$($CA.DnsHostname)/certsrv/"
    if ((Test-UrlExists -Url $httpUrl -AuthType 'NTLM') -and (Test-UrlExists -Url $httpUrl -AuthType 'Negotiate')) {
        $vulnerabilities[8] = 'The CA supports HTTP web enrollment without channel binding.'
    }
    elseif ((Test-UrlExists -Url $httpsUrl -AuthType 'NTLM') -and (Test-UrlExists -Url $httpsUrl -AuthType 'Negotiate')) {
        $vulnerabilities[8] = 'The CA supports HTTPS web enrollment without channel binding.'
    }

    if ($CA.RpcRequestEncryption -eq 'Disabled') {
        $vulnerabilities[11] = 'The CA does not enforce encryption on the ICertPassage RPC interface.'
    }

    if (@($CA.DisabledExtensions) -contains $script:CommonOids.NtdsCaSecurityExt) {
        $vulnerabilities[16] = 'The CA has disabled the security extension.'
    }

    $CA.Vulnerabilities = $vulnerabilities
}

function Get-EnterpriseCAs {
    param(
        [string]$ConfigurationPath,
        [string]$Server,
        [string]$AuthorityName,
        [string[]]$UserSids
    )

    $ldapPath = Join-LdapPath -Server $Server -DistinguishedName "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigurationPath"
    $filter = if ([string]::IsNullOrWhiteSpace($AuthorityName)) { '(objectCategory=pKIEnrollmentService)' } else { "(&(objectCategory=pKIEnrollmentService)(name=$($AuthorityName.Split('\')[-1])))" }
    $properties = @('name', 'distinguishedName', 'objectGuid', 'dnshostname', 'flags', 'caCertificate', 'certificateTemplates', 'nTSecurityDescriptor')
    $results = Search-LdapObjects -LdapPath $ldapPath -Filter $filter -Properties $properties
    $cas = New-Object System.Collections.Generic.List[object]

    foreach ($result in $results) {
        $dn = [string](Get-SearchValue -SearchResult $result -Name 'distinguishedname')
        $name = [string](Get-SearchValue -SearchResult $result -Name 'name')
        $dnsHostName = [string](Get-SearchValue -SearchResult $result -Name 'dnshostname')
        $certificates = @(Get-Certificates -SearchResult $result)

        $ca = [pscustomobject]@{
            DistinguishedName        = $dn
            Name                     = $name
            DomainName               = Get-DomainNameFromDn -DistinguishedName $dn
            Guid                     = Get-SearchGuid -SearchResult $result
            DnsHostname              = $dnsHostName
            FullName                 = if ($dnsHostName) { "$dnsHostName\$name" } else { "\$name" }
            FlagsRaw                 = ConvertTo-UInt32 (Get-SearchValue -SearchResult $result -Name 'flags')
            Certificates             = @($certificates | Where-Object { $null -ne $_ })
            SecurityDescriptor       = Get-SecurityDescriptor -SearchResult $result
            Templates                = @(Get-SearchValues -SearchResult $result -Name 'certificatetemplates' | ForEach-Object { [string]$_ })
            UserSpecifiedSan         = $null
            RpcRequestEncryption     = $null
            RpcRequestRestrictions   = @()
            DisabledExtensions       = @()
            ServerSecurityDescriptor = $null
            EnrollmentAgentSecurity  = $null
            Vulnerabilities          = [ordered]@{}
        }

        Update-CaRuntimeInfo -CA $ca -UserSids $UserSids
        [void]$cas.Add($ca)
    }

    return @($cas.ToArray())
}

function Get-RootCAs {
    param(
        [string]$ConfigurationPath,
        [string]$Server
    )

    $ldapPath = Join-LdapPath -Server $Server -DistinguishedName "CN=Certification Authorities,CN=Public Key Services,CN=Services,$ConfigurationPath"
    $results = Search-LdapObjects -LdapPath $ldapPath -Filter '(objectCategory=certificationAuthority)' -Properties @('name', 'distinguishedName', 'objectGuid', 'flags', 'caCertificate', 'nTSecurityDescriptor')

    foreach ($result in $results) {
        [pscustomobject]@{
            DistinguishedName  = [string](Get-SearchValue -SearchResult $result -Name 'distinguishedname')
            Name               = [string](Get-SearchValue -SearchResult $result -Name 'name')
            Certificates       = @(Get-Certificates -SearchResult $result)
            SecurityDescriptor = Get-SecurityDescriptor -SearchResult $result
        }
    }
}

function Get-NtAuthCertificates {
    param(
        [string]$ConfigurationPath,
        [string]$Server
    )

    $ldapPath = Join-LdapPath -Server $Server -DistinguishedName "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$ConfigurationPath"
    $results = Search-LdapObjects -LdapPath $ldapPath -Filter '(objectClass=certificationAuthority)' -Properties @('name', 'distinguishedName', 'objectGuid', 'caCertificate', 'nTSecurityDescriptor')
    $items = @($results)

    if ($items.Count -ne 1) {
        throw 'More than one NTAuthCertificate object found'
    }

    $result = $items[0]
    return [pscustomobject]@{
        DistinguishedName  = [string](Get-SearchValue -SearchResult $result -Name 'distinguishedname')
        Name               = [string](Get-SearchValue -SearchResult $result -Name 'name')
        Certificates       = @(Get-Certificates -SearchResult $result)
        SecurityDescriptor = Get-SecurityDescriptor -SearchResult $result
    }
}

function Get-FriendlyOid {
    param([string]$Oid)

    if ([string]::IsNullOrWhiteSpace($Oid)) {
        return $null
    }

    try {
        $friendly = (New-Object System.Security.Cryptography.Oid -ArgumentList $Oid).FriendlyName
        if (-not [string]::IsNullOrWhiteSpace($friendly)) {
            return $friendly
        }
    }
    catch {
    }

    return $Oid
}

function Write-CertificateInfo {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    Write-Host "    Cert SubjectName              : $($Certificate.SubjectName.Name)"
    Write-Host "    Cert Thumbprint               : $($Certificate.Thumbprint)"
    Write-Host "    Cert Serial                   : $($Certificate.SerialNumber)"
    Write-Host "    Cert Start Date               : $($Certificate.NotBefore)"
    Write-Host "    Cert End Date                 : $($Certificate.NotAfter)"

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    [void]$chain.Build($Certificate)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($element in $chain.ChainElements) {
        $names.Insert(0, $element.Certificate.SubjectName.Name.Replace(' ', ''))
    }

    Write-Host "    Cert Chain                    : $($names -join ' -> ')"
}

function Convert-CaRightsToString {
    param([uint32]$Rights)

    $names = foreach ($key in $script:CaRights.Keys) {
        if (Test-Flag -Value $Rights -Flag ([uint32]$key)) {
            $script:CaRights[$key]
        }
    }

    if (@($names).Count -eq 0) {
        return [string]$Rights
    }

    return (@($names) -join ', ')
}

function ConvertTo-EnrollmentAgentRestriction {
    param([System.Security.AccessControl.CommonAce]$Ace)

    $bytes = $Ace.GetOpaque()
    $index = 0
    $sidCount = [BitConverter]::ToUInt32($bytes, $index)
    $index += 4

    $targets = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $sidCount; $i++) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList ($bytes, $index)
        [void]$targets.Add($sid.ToString())
        $index += $sid.BinaryLength
    }

    $templateName = '<All>'
    if ($index -lt $bytes.Length) {
        $templateName = [Text.Encoding]::Unicode.GetString($bytes, $index, ($bytes.Length - $index - 2)).Replace("`0", '')
    }

    return [pscustomobject]@{
        Agent    = $Ace.SecurityIdentifier.ToString()
        Template = $templateName
        Targets  = @($targets.ToArray())
    }
}

function Write-EnterpriseCaInfo {
    param(
        [pscustomobject]$CA,
        [bool]$ShouldHideAdmins,
        [bool]$ShouldShowAllPermissions
    )

    Write-Host "    Enterprise CA Name            : $($CA.Name)"
    Write-Host "    DNS Hostname                  : $($CA.DnsHostname)"
    Write-Host "    FullName                      : $($CA.FullName)"
    Write-Host "    Flags                         : $(ConvertTo-FlagString -Value $CA.FlagsRaw -Map $script:CaFlags)"

    foreach ($certificate in @($CA.Certificates)) {
        Write-CertificateInfo -Certificate $certificate
    }

    Write-Host "    User Specifies SAN            : $($CA.UserSpecifiedSan)"
    Write-Host "    RPC Request Encryption        : $($CA.RpcRequestEncryption)"

    if (@($CA.RpcRequestRestrictions).Count -gt 0) {
        Write-Host "    RPC Request Restrictions      : $($CA.RpcRequestRestrictions -join ', ')"
    }

    if (@($CA.DisabledExtensions).Count -gt 0) {
        $disabled = @($CA.DisabledExtensions | ForEach-Object { "$(Get-FriendlyOid -Oid $_) ($_) " } | Sort-Object)
        Write-Host "    Disabled Extensions           : $($disabled -join "`n                                    ")"
    }

    if ($CA.Vulnerabilities.Count -gt 0) {
        Write-Host '    Vulnerabilities'
        foreach ($key in @($CA.Vulnerabilities.Keys | Sort-Object)) {
            Write-Host ("      {0,-27} : {1}" -f "ESC$key", $CA.Vulnerabilities[$key])
        }
    }

    Write-Host '    CA Permissions'

    if ($null -ne $CA.ServerSecurityDescriptor) {
        $ownerSid = $CA.ServerSecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        Write-Host "      Owner: $(Get-UserSidString -Sid $ownerSid)"
        Write-Host ''

        if (-not $ShouldShowAllPermissions) {
            Write-Host ("      {0,-6} {1,-42} Principal" -f 'Access', 'Rights')
        }

        foreach ($ace in $CA.ServerSecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            $sid = $ace.IdentityReference.Value
            if ($ShouldHideAdmins -and (Test-IsAdminSid -Sid $sid)) {
                continue
            }

            $rights = Convert-CaRightsToString -Rights ([uint32]$ace.ActiveDirectoryRights)
            if (-not $ShouldShowAllPermissions) {
                Write-Host ("      {0,-6} {1,-42} {2}" -f $ace.AccessControlType, $rights, (Get-UserSidString -Sid $sid))
            }
            else {
                Write-Host "      Identity                    : $(Get-UserSidString -Sid $sid)"
                Write-Host "        AccessControlType         : $($ace.AccessControlType)"
                Write-Host "        Rights                    : $rights"
                Write-Host "        ObjectType                : $($ace.ObjectType)"
                Write-Host "        IsInherited               : $($ace.IsInherited)"
                Write-Host "        InheritedObjectType       : $($ace.InheritedObjectType)"
                Write-Host "        InheritanceFlags          : $($ace.InheritanceFlags)"
                Write-Host "        PropagationFlags          : $($ace.PropagationFlags)"
                Write-Host ''
            }
        }

        if ($null -eq $CA.EnrollmentAgentSecurity) {
            Write-Host '    Enrollment Agent Restrictions : None'
        }
        else {
            Write-Host '    Enrollment Agent Restrictions :'
            foreach ($ace in $CA.EnrollmentAgentSecurity.DiscretionaryAcl) {
                $entry = ConvertTo-EnrollmentAgentRestriction -Ace $ace
                Write-Host "      $(Get-UserSidString -Sid $entry.Agent)"
                Write-Host "        Template : $($entry.Template)"
                Write-Host '        Targets  :'

                foreach ($target in $entry.Targets) {
                    Write-Host "          $(Get-UserSidString -Sid $target -Padding 31)"
                }
            }
        }

        Write-Host ''
    }
}

function Write-CAWebServices {
    param($WebServices)

    $joinSep = "`n                                    "

    if ($WebServices.LegacyAspEnrollmentUrls.Count -gt 0) {
        Write-Host "    Legacy ASP Enrollment Website : $($WebServices.LegacyAspEnrollmentUrls.ToArray() -join $joinSep)"
        Write-Host ''
    }

    if ($WebServices.EnrollmentWebServiceUrls.Count -gt 0) {
        Write-Host "    Enrollment Web Service        : $($WebServices.EnrollmentWebServiceUrls.ToArray() -join $joinSep)"
        Write-Host ''
    }

    if ($WebServices.EnrollmentPolicyWebServiceUrls.Count -gt 0) {
        Write-Host "    Enrollment Policy Web Service : $($WebServices.EnrollmentPolicyWebServiceUrls.ToArray() -join $joinSep)"
        Write-Host ''
    }

    if ($WebServices.NetworkDeviceEnrollmentServiceUrls.Count -gt 0) {
        Write-Host "    NDES Web Service              : $($WebServices.NetworkDeviceEnrollmentServiceUrls.ToArray() -join $joinSep)"
        Write-Host ''
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

function Invoke-EnumCas {
    Write-Host '[*] Action: Find certificate authorities'

    if (-not [string]::IsNullOrWhiteSpace($CAName) -and $CAName -notmatch '\\') {
        Write-Host "[X] The 'certificate authority' parameter is not of the format 'SERVER\CA-NAME'."
        return
    }

    if (-not [string]::IsNullOrWhiteSpace($Domain) -and $Domain -notmatch '\.') {
        Write-Host "[X] The 'domain' parameter is not a fully qualified domain name."
        return
    }

    $configurationPath = Get-LdapConfigurationPath -TargetDomain $Domain
    Write-Host "[*] Using the search base '$configurationPath'"

    $userSids = $null
    if ($CurrentUser) {
        $userSids = Get-CurrentUserSids
    }
    elseif (-not [string]::IsNullOrWhiteSpace($TargetUser)) {
        $userSids = Get-TargetUserSids -Identity $TargetUser -TargetDomain $Domain
    }

    if ($null -eq $userSids) {
        Write-Host '[*] Classifying vulnerabilities in the context of built-in low-privileged domain groups.'
    }

    Write-Host ''
    Write-Host '[*] Root CAs'

    $rootCas = @(Get-RootCAs -ConfigurationPath $configurationPath -Server $LdapServer)
    foreach ($ca in $rootCas) {
        foreach ($cert in @($ca.Certificates)) {
            Write-Host ''
            Write-CertificateInfo -Certificate $cert
        }
    }

    Write-Host ''
    Write-Host '[*] NTAuthCertificates - Certificates that enable authentication:'

    $ntAuth = Get-NtAuthCertificates -ConfigurationPath $configurationPath -Server $LdapServer
    if ($null -eq $ntAuth.Certificates -or @($ntAuth.Certificates).Count -eq 0) {
        Write-Host ''
        Write-Host '    There are no NTAuthCertificates'
    }
    else {
        foreach ($cert in @($ntAuth.Certificates)) {
            Write-Host ''
            Write-CertificateInfo -Certificate $cert
        }
    }

    $cas = @(Get-EnterpriseCAs -ConfigurationPath $configurationPath -Server $LdapServer -AuthorityName $CAName -UserSids $userSids)

    if ($FilterVulnerable) {
        $cas = @($cas | Where-Object { $_.Vulnerabilities.Count -gt 0 })
    }

    if ($cas.Count -eq 0) {
        Write-Host ''
        Write-Host '[+] No enterprise certificate authorities found with the current filter parameters.'
        return
    }

    Write-Host ''
    Write-Host '[*] Enterprise/enrollment certificate authorities:'

    foreach ($ca in $cas) {
        Write-Host ''
        Write-EnterpriseCaInfo -CA $ca -ShouldHideAdmins $HideAdmins.IsPresent -ShouldShowAllPermissions $ShowAllPermissions.IsPresent

        if (-not $SkipWebServiceChecks) {
            Write-CAWebServices -WebServices (Get-CaWebServices -CA $ca)
        }

        Write-Host '    Enabled Certificate Templates:'

        if ($null -eq $ca.Templates -or @($ca.Templates).Count -eq 0) {
            Write-Host '        There are no enabled Certificate Templates'
        }
        else {
            Write-Host "        $(@($ca.Templates) -join "`n        ")"
        }
    }
}

Export-ConsoleOutput -Path $OutFile -ScriptBlock {
    Invoke-EnumCas
}
