[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Alias('CA')]
    [string]$CAName,

    [Alias('TemplateName')]
    [string]$Template,

    [string]$Domain,

    [Alias('DomainController', 'Server')]
    [string]$LdapServer,

    [Parameter(ParameterSetName = 'MarkCurrentUser')]
    [switch]$CurrentUser,

    [Parameter(ParameterSetName = 'MarkTargetUser')]
    [string]$TargetUser,

    [switch]$FilterEnabled,
    [switch]$FilterVulnerable,
    [switch]$FilterRequestAgent,
    [switch]$FilterClientAuth,
    [Alias('FilterSupplySubject')]
    [switch]$FilterEnrolleeSuppliesSubject,
    [switch]$FilterManagerApproval,
    [switch]$HideAdmins,
    [switch]$ShowAllPermissions,

    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$script:CommonOids = @{
    AnyPurpose                 = '2.5.29.37.0'
    ClientAuthentication       = '1.3.6.1.5.5.7.3.2'
    PKINITClientAuthentication = '1.3.6.1.5.2.3.4'
    SmartcardLogon             = '1.3.6.1.4.1.311.20.2.2'
    CertificateRequestAgent    = '1.3.6.1.4.1.311.20.2.1'
    NtdsCaSecurityExt          = '1.3.6.1.4.1.311.25.2'
}

$script:NameFlags = @{
    ENROLLEE_SUPPLIES_SUBJECT              = [uint32]0x00000001
    ADD_EMAIL                              = [uint32]0x00000002
    ADD_OBJ_GUID                           = [uint32]0x00000004
    OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = [uint32]0x00000008
    ADD_DIRECTORY_PATH                     = [uint32]0x00000100
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME     = [uint32]0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS         = [uint32]0x00400000
    SUBJECT_ALT_REQUIRE_SPN                = [uint32]0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID     = [uint32]0x01000000
    SUBJECT_ALT_REQUIRE_UPN                = [uint32]0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL              = [uint32]0x04000000
    SUBJECT_ALT_REQUIRE_DNS                = [uint32]0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN              = [uint32]0x10000000
    SUBJECT_REQUIRE_EMAIL                  = [uint32]0x20000000
    SUBJECT_REQUIRE_COMMON_NAME            = [uint32]0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH         = [uint32]2147483648
}

$script:EnrollmentFlags = @{
    INCLUDE_SYMMETRIC_ALGORITHMS                              = [uint32]0x00000001
    PEND_ALL_REQUESTS                                         = [uint32]0x00000002
    PUBLISH_TO_KRA_CONTAINER                                  = [uint32]0x00000004
    PUBLISH_TO_DS                                             = [uint32]0x00000008
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE                 = [uint32]0x00000010
    AUTO_ENROLLMENT                                           = [uint32]0x00000020
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT                   = [uint32]0x00000040
    DOMAIN_AUTHENTICATION_NOT_REQUIRED                        = [uint32]0x00000080
    USER_INTERACTION_REQUIRED                                 = [uint32]0x00000100
    ADD_TEMPLATE_NAME                                         = [uint32]0x00000200
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE            = [uint32]0x00000400
    ALLOW_ENROLL_ON_BEHALF_OF                                 = [uint32]0x00000800
    ADD_OCSP_NOCHECK                                          = [uint32]0x00001000
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL          = [uint32]0x00002000
    NOREVOCATIONINFOINISSUEDCERTS                             = [uint32]0x00004000
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS                    = [uint32]0x00008000
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = [uint32]0x00010000
    ISSUANCE_POLICIES_FROM_REQUEST                            = [uint32]0x00020000
    SKIP_AUTO_RENEWAL                                         = [uint32]0x00040000
    NO_SECURITY_EXTENSION                                     = [uint32]0x00080000
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
    NO_REMOTE_ICERTREQUEST      = [uint32]0x00000002
    NO_LOCAL_ICERTREQUEST       = [uint32]0x00000004
    NO_RPC_ICERTREQUEST         = [uint32]0x00000008
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

function Initialize-EnumTemplatesHttpInterop {
    if ('CertifyPowerShell.EnumTemplatesHttpUtilQuiet' -as [type]) {
        return
    }

    Add-Type -ReferencedAssemblies 'System.Net.Http' -TypeDefinition @'
using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;

namespace CertifyPowerShell
{
    public static class EnumTemplatesHttpUtilQuiet
    {
        struct SECURITY_INTEGER
        {
            public uint LowPart;
            public uint HighPart;
        };

        struct SECURITY_HANDLE
        {
            public IntPtr LowPart;
            public IntPtr HighPart;
        };

        struct SecBuffer : IDisposable
        {
            public int cbBuffer;
            public int BufferType;
            public IntPtr pvBuffer;

            public SecBuffer(int size) : this(new byte[size])
            {
            }

            public SecBuffer(byte[] bytes) : this(bytes, 2)
            {
            }

            public SecBuffer(byte[] bytes, int type)
            {
                cbBuffer = bytes.Length;
                BufferType = type;
                pvBuffer = Marshal.AllocHGlobal(cbBuffer);
                Marshal.Copy(bytes, 0, pvBuffer, cbBuffer);
            }

            public void Dispose()
            {
                if (pvBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvBuffer);
                    pvBuffer = IntPtr.Zero;
                }
            }
        }

        struct SecBufferDesc : IDisposable
        {
            public uint ulVersion;
            public uint cBuffers;
            public IntPtr pBuffers;

            public SecBufferDesc(int size)
            {
                ulVersion = 0;
                cBuffers = 1;
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)));
                Marshal.StructureToPtr(new SecBuffer(size), pBuffers, false);
            }

            public SecBufferDesc(byte[] bytes)
            {
                ulVersion = 0;
                cBuffers = 1;
                pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecBuffer)));
                Marshal.StructureToPtr(new SecBuffer(bytes), pBuffers, false);
            }

            public void Dispose()
            {
                if (pBuffers != IntPtr.Zero)
                {
                    if (cBuffers == 1)
                        Marshal.PtrToStructure(pBuffers, typeof(SecBuffer)).GetType();

                    var buffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                    buffer.Dispose();
                    Marshal.FreeHGlobal(pBuffers);
                    pBuffers = IntPtr.Zero;
                }
            }

            public byte[] GetSecBufferByteArray()
            {
                byte[] result = null;

                if (pBuffers == IntPtr.Zero)
                    throw new InvalidOperationException("Object has already been disposed.");

                var buffer = (SecBuffer)Marshal.PtrToStructure(pBuffers, typeof(SecBuffer));
                if (buffer.cbBuffer > 0)
                {
                    result = new byte[buffer.cbBuffer];
                    Marshal.Copy(buffer.pvBuffer, result, 0, buffer.cbBuffer);
                }

                return result;
            }
        }

        [DllImport("secur32.dll")]
        static extern int AcquireCredentialsHandle(string pszPrincipal, string pszPackage, uint fCredentialUse, IntPtr pvLogonID, IntPtr pAuthData,
            IntPtr pGetKeyFn, IntPtr pvGetKeyArgument, out SECURITY_HANDLE phCredential, out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(SECURITY_HANDLE phCredential, IntPtr phContext, string pszTargetName, uint fContextReq, uint Reserved1,
            uint TargetDataRep, IntPtr pInput, uint Reserved2, out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput, out uint pfContextAttr, out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern int InitializeSecurityContext(SECURITY_HANDLE phCredential, SECURITY_HANDLE phContext, string pszTargetName, uint fContextReq, uint Reserved1,
            uint TargetDataRep, SecBufferDesc pInput, uint Reserved2, out SECURITY_HANDLE phNewContext, out SecBufferDesc pOutput, out uint pfContextAttr, out SECURITY_INTEGER ptsExpiry);

        [DllImport("secur32.dll")]
        static extern int DeleteSecurityContext(SECURITY_HANDLE phContext);

        [DllImport("secur32.dll")]
        static extern int FreeCredentialsHandle(SECURITY_HANDLE phCredential);

        const int MAX_TOKEN_SIZE = 12288;

        public static bool AuthWithChannelBinding(string url)
        {
            var handler = new HttpClientHandler
            {
                Credentials = new CredentialCache() { { new Uri(url), "NTLM", CredentialCache.DefaultNetworkCredentials } },
                PreAuthenticate = true,
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            using (var client = new HttpClient(handler))
            {
                try
                {
                    var response = SynchronizeHttpTask(() => client.GetAsync(url));
                    return response.StatusCode == HttpStatusCode.OK;
                }
                catch (Exception)
                {
                    return false;
                }
            }
        }

        public static bool AuthWithoutChannelBinding(string url)
        {
            var handler = new HttpClientHandler
            {
                UseDefaultCredentials = false,
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };

            using (var client = new HttpClient(handler))
            {
                SECURITY_HANDLE credHandle;
                SECURITY_INTEGER clientLifeTime;
                if (AcquireCredentialsHandle(WindowsIdentity.GetCurrent().Name, "NTLM", 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out credHandle, out clientLifeTime) != 0)
                {
                    return false;
                }

                var clientContext = new SECURITY_HANDLE() { LowPart = IntPtr.Zero, HighPart = IntPtr.Zero };

                try
                {
                    uint contextAttributes;
                    string ntlmMessage = HttpInitializeSecurityContext(credHandle, ref clientContext, out contextAttributes, out clientLifeTime, null);
                    if (string.IsNullOrEmpty(ntlmMessage))
                        return false;

                    var requestMessage = new HttpRequestMessage(HttpMethod.Get, url);
                    requestMessage.Headers.Add("Authorization", ntlmMessage);

                    try
                    {
                        var response = SynchronizeHttpTask(() => client.SendAsync(requestMessage));
                        if (!response.Headers.Contains("WWW-Authenticate"))
                        {
                            return false;
                        }

                        ntlmMessage = response.Headers.GetValues("WWW-Authenticate").First();
                    }
                    catch (Exception)
                    {
                        return false;
                    }

                    ntlmMessage = HttpInitializeSecurityContext(credHandle, ref clientContext, out contextAttributes, out clientLifeTime, ntlmMessage);
                    if (string.IsNullOrEmpty(ntlmMessage))
                        return false;

                    requestMessage = new HttpRequestMessage(HttpMethod.Get, url);
                    requestMessage.Headers.Add("Authorization", ntlmMessage);

                    try
                    {
                        var response = SynchronizeHttpTask(() => client.SendAsync(requestMessage));
                        return response.StatusCode == HttpStatusCode.OK;
                    }
                    catch (Exception)
                    {
                        return false;
                    }
                }
                finally
                {
                    if (clientContext.LowPart != IntPtr.Zero || clientContext.HighPart != IntPtr.Zero)
                        DeleteSecurityContext(clientContext);

                    if (credHandle.LowPart != IntPtr.Zero || credHandle.HighPart != IntPtr.Zero)
                        FreeCredentialsHandle(credHandle);
                }
            }
        }

        private static string HttpInitializeSecurityContext(SECURITY_HANDLE credHandle, ref SECURITY_HANDLE clientContext, out uint contextAttributes, out SECURITY_INTEGER clientLifeTime, string message)
        {
            SecBufferDesc clientToken = new SecBufferDesc(MAX_TOKEN_SIZE);

            if (message == null)
            {
                int res = InitializeSecurityContext(credHandle, IntPtr.Zero, WindowsIdentity.GetCurrent().Name, 0x00000800, 0, 0x10, IntPtr.Zero, 0, out clientContext, out clientToken, out contextAttributes, out clientLifeTime);
                if (res != 0x00090312)
                {
                    return null;
                }
            }
            else
            {
                var serverToken = new SecBufferDesc(Convert.FromBase64String(message.Replace("NTLM ", "")));
                int res = InitializeSecurityContext(credHandle, clientContext, WindowsIdentity.GetCurrent().Name, 0x00000800, 0, 0x10, serverToken, 0, out clientContext, out clientToken, out contextAttributes, out clientLifeTime);
                if (res != 0x00000000)
                {
                    return null;
                }
            }

            byte[] ntlmMessage = clientToken.GetSecBufferByteArray();
            return "NTLM " + Convert.ToBase64String(ntlmMessage);
        }

        private static HttpResponseMessage SynchronizeHttpTask(Func<Task<HttpResponseMessage>> fn)
        {
            var task = Task.Run(() => fn());

            try
            {
                task.Wait();
                return task.Result;
            }
            catch (AggregateException e)
            {
                throw e.InnerException ?? e;
            }
        }
    }
}
'@
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
        $keyIsFlag = $false
        [uint32]$keyFlag = 0
        if ([uint32]::TryParse([string]$entry.Key, [ref]$keyFlag)) {
            $keyIsFlag = $true
        }

        if ($keyIsFlag) {
            $flag = $keyFlag
            $name = [string]$entry.Value
        }
        else {
            $flag = [uint32]$entry.Value
            $name = [string]$entry.Key
        }

        if (Test-Flag -Value $Value -Flag $flag) {
            $name
        }
    }

    if (@($names).Count -eq 0) {
        return 'NONE'
    }

    return (@($names) -join ', ')
}

function ConvertTo-Int32 {
    param($Value)

    if ($null -eq $Value) {
        return 0
    }

    [int]$result = 0
    if ([int]::TryParse([string]$Value, [ref]$result)) {
        return $result
    }

    return 0
}

function ConvertTo-UInt32FromSignedString {
    param($Value)

    if ($null -eq $Value) {
        return [uint32]0
    }

    [uint32]$unsigned = 0
    if ([uint32]::TryParse([string]$Value, [ref]$unsigned)) {
        return $unsigned
    }

    [int]$signed = 0
    if ([int]::TryParse([string]$Value, [ref]$signed)) {
        return [BitConverter]::ToUInt32([BitConverter]::GetBytes($signed), 0)
    }

    return [uint32]0
}

function ConvertTo-UInt32String {
    param($Value)

    if ($null -eq $Value) {
        return [uint32]0
    }

    [uint32]$unsigned = 0
    if ([uint32]::TryParse([string]$Value, [ref]$unsigned)) {
        return $unsigned
    }

    [int]$signed = 0
    if ([int]::TryParse([string]$Value, [ref]$signed)) {
        return [BitConverter]::ToUInt32([BitConverter]::GetBytes($signed), 0)
    }

    return [uint32]0
}

function Convert-PkiPeriod {
    param([byte[]]$Bytes)

    if ($null -eq $Bytes) {
        return $null
    }

    try {
        $copy = [byte[]]$Bytes.Clone()
        [Array]::Reverse($copy)
        $hex = [BitConverter]::ToString($copy).Replace('-', '')
        $value = [Convert]::ToInt64($hex, 16) * -0.0000001

        if (($value % 31536000 -eq 0) -and ($value / 31536000 -ge 1)) {
            $n = $value / 31536000
            if ($n -eq 1) { return '1 year' }
            return "$n years"
        }

        if (($value % 2592000 -eq 0) -and ($value / 2592000 -ge 1)) {
            $n = $value / 2592000
            if ($n -eq 1) { return '1 month' }
            return "$n months"
        }

        if (($value % 604800 -eq 0) -and ($value / 604800 -ge 1)) {
            $n = $value / 604800
            if ($n -eq 1) { return '1 week' }
            return "$n weeks"
        }

        if (($value % 86400 -eq 0) -and ($value / 86400 -ge 1)) {
            $n = $value / 86400
            if ($n -eq 1) { return '1 day' }
            return "$n days"
        }

        if (($value % 3600 -eq 0) -and ($value / 3600 -ge 1)) {
            $n = $value / 3600
            if ($n -eq 1) { return '1 hour' }
            return "$n hours"
        }

        return ''
    }
    catch {
        return 'ERROR'
    }
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

function Get-SearchGuid {
    param(
        [System.DirectoryServices.SearchResult]$SearchResult,
        [string]$Name = 'objectguid'
    )

    $raw = Get-SearchValue -SearchResult $SearchResult -Name $Name
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

function Get-AccessControlTypeFromGuid {
    param([string]$Guid)

    switch ($Guid) {
        '0e10c968-78fb-11d2-90d4-00c04f79dc55' { return 'Enrollment' }
        'a05b8cc2-17bc-4802-a710-e7c15ab866a2' { return 'AutoEnrollment' }
        '00000000-0000-0000-0000-000000000000' { return 'All' }
        default { return $null }
    }
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

function Test-AceMatchesScope {
    param(
        [System.DirectoryServices.ActiveDirectoryAccessRule]$Ace,
        [string[]]$UserSids
    )

    $sid = $Ace.IdentityReference.Value
    if ($null -eq $UserSids) {
        return Test-IsLowPrivSid -Sid $sid
    }

    return $UserSids -contains $sid
}

function Get-TemplateVulnerabilities {
    param(
        [pscustomobject]$TemplateObject,
        [string[]]$UserSids
    )

    $vulnerabilities = [ordered]@{}
    $hasEnrollRights = $false
    $sd = $TemplateObject.SecurityDescriptor

    if ($null -ne $sd) {
        $ownerSid = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
        $esc4 = (($null -eq $UserSids -and (Test-IsLowPrivSid -Sid $ownerSid)) -or ($null -ne $UserSids -and $UserSids -contains $ownerSid))

        foreach ($ace in $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
                continue
            }

            if (-not (Test-AceMatchesScope -Ace $ace -UserSids $UserSids)) {
                continue
            }

            $rights = $ace.ActiveDirectoryRights
            $objectType = $ace.ObjectType.ToString()
            $allType = '00000000-0000-0000-0000-000000000000'
            $enrollmentType = '0e10c968-78fb-11d2-90d4-00c04f79dc55'

            if ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -or
                $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner) -or
                $rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or
                ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and $objectType -eq $allType)) {
                $esc4 = $true
            }

            if ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -and ($objectType -eq $enrollmentType -or $objectType -eq $allType)) {
                $hasEnrollRights = $true
            }
        }

        if ($esc4) {
            $vulnerabilities['4'] = 'The template has insecure delegated permissions.'
        }
    }

    $managerApproval = Test-Flag -Value $TemplateObject.EnrollmentFlag -Flag $script:EnrollmentFlags.PEND_ALL_REQUESTS
    $clientAuthOids = @(
        $script:CommonOids.ClientAuthentication,
        $script:CommonOids.PKINITClientAuthentication,
        $script:CommonOids.SmartcardLogon,
        $script:CommonOids.AnyPurpose
    )

    $eku = @($TemplateObject.ExtendedKeyUsage)
    $hasClientAuth = ($null -eq $TemplateObject.ExtendedKeyUsage) -or $eku.Count -eq 0 -or (@($eku | Where-Object { $clientAuthOids -contains $_ }).Count -gt 0)

    if (-not $managerApproval -and $TemplateObject.AuthorizedSignatures -eq 0 -and $hasEnrollRights) {
        if ($hasClientAuth -and (Test-Flag -Value $TemplateObject.CertificateNameFlag -Flag $script:NameFlags.ENROLLEE_SUPPLIES_SUBJECT)) {
            $vulnerabilities['1'] = 'The template has a client authentication EKU and allows enrollees to supply subject.'
        }

        if (-not (Test-Flag -Value $TemplateObject.CertificateNameFlag -Flag $script:NameFlags.ENROLLEE_SUPPLIES_SUBJECT)) {
            if ($null -eq $TemplateObject.ExtendedKeyUsage -or $eku.Count -eq 0) {
                $vulnerabilities['2'] = 'The template has no EKUs (Subordinate CA).'
            }
            elseif ($eku -contains $script:CommonOids.AnyPurpose) {
                $vulnerabilities['2'] = "The template has the 'Any Purpose' EKU."
            }
        }

        if ($null -ne $TemplateObject.ExtendedKeyUsage -and $eku -contains $script:CommonOids.CertificateRequestAgent) {
            if ($eku -contains $script:CommonOids.AnyPurpose) {
                $vulnerabilities['3'] = "The template has the 'Certificate Request Agent' EKU, but only works for schema version 1 templates."
            }
            else {
                $vulnerabilities['3'] = "The template has the 'Certificate Request Agent' EKU."
            }
        }

        if ($hasClientAuth -and (Test-Flag -Value $TemplateObject.EnrollmentFlag -Flag $script:EnrollmentFlags.NO_SECURITY_EXTENSION)) {
            $requiresAlt = (Test-Flag -Value $TemplateObject.CertificateNameFlag -Flag $script:NameFlags.SUBJECT_ALT_REQUIRE_UPN) -or
                (Test-Flag -Value $TemplateObject.CertificateNameFlag -Flag $script:NameFlags.SUBJECT_ALT_REQUIRE_SPN) -or
                (Test-Flag -Value $TemplateObject.CertificateNameFlag -Flag $script:NameFlags.SUBJECT_ALT_REQUIRE_DNS)

            if ($requiresAlt) {
                $vulnerabilities['9'] = 'The template has a client authentication EKU and no security extension.'
            }
            else {
                $vulnerabilities['9'] = 'The template has a client authentication EKU and no security extension, but only works with ESC6.'
            }
        }

        $issuancePoliciesWithGroups = @($TemplateObject.IssuancePolicies | Where-Object { -not [string]::IsNullOrWhiteSpace($_.GroupLink) })
        $authOidsForEsc13 = @($script:CommonOids.ClientAuthentication, $script:CommonOids.PKINITClientAuthentication, $script:CommonOids.SmartcardLogon)
        if ($null -ne $TemplateObject.ExtendedKeyUsage -and @($eku | Where-Object { $authOidsForEsc13 -contains $_ }).Count -gt 0 -and $issuancePoliciesWithGroups.Count -gt 0) {
            $vulnerabilities['13'] = 'The template has client authentication and an issuance policy linked to one or more domain group(s).'
        }

        if ($TemplateObject.SchemaVersion -eq 1 -and (Test-Flag -Value $TemplateObject.CertificateNameFlag -Flag $script:NameFlags.ENROLLEE_SUPPLIES_SUBJECT)) {
            $vulnerabilities['15'] = 'The template has schema version 1 and allows enrollees to supply subject.'
        }
    }

    return $vulnerabilities
}

function Get-EnterpriseOid {
    param(
        [string]$Oid,
        [string]$ConfigurationPath,
        [string]$Server
    )

    $ldapPath = Join-LdapPath -Server $Server -DistinguishedName "CN=OID,CN=Public Key Services,CN=Services,$ConfigurationPath"
    $results = Search-LdapObjects -LdapPath $ldapPath -Filter "(msPKI-Cert-Template-OID=$Oid)" -Properties @('name', 'displayName', 'msPKI-Cert-Template-OID', 'msDS-OIDToGroupLink', 'objectGuid', 'distinguishedName', 'nTSecurityDescriptor')

    foreach ($result in $results) {
        return [pscustomobject]@{
            DistinguishedName  = [string](Get-SearchValue -SearchResult $result -Name 'distinguishedname')
            Name               = [string](Get-SearchValue -SearchResult $result -Name 'name')
            Guid               = Get-SearchGuid -SearchResult $result
            DisplayName        = [string](Get-SearchValue -SearchResult $result -Name 'displayname')
            Oid                = [string](Get-SearchValue -SearchResult $result -Name 'mspki-cert-template-oid')
            GroupLink          = [string](Get-SearchValue -SearchResult $result -Name 'msds-oidtogrouplink')
            SecurityDescriptor = Get-SecurityDescriptor -SearchResult $result
        }
    }

    return $null
}

function Get-CertificateTemplates {
    param(
        [string]$ConfigurationPath,
        [string]$Server,
        [string[]]$UserSids
    )

    $ldapPath = Join-LdapPath -Server $Server -DistinguishedName "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigurationPath"
    $properties = @(
        'name',
        'displayName',
        'distinguishedName',
        'objectGuid',
        'msPKI-Template-Schema-Version',
        'pKIExpirationPeriod',
        'pKIOverlapPeriod',
        'msPKI-Cert-Template-OID',
        'msPKI-Certificate-Name-Flag',
        'msPKI-Enrollment-Flag',
        'pKIExtendedKeyUsage',
        'msPKI-RA-Signature',
        'msPKI-RA-Application-Policies',
        'msPKI-RA-Policies',
        'msPKI-Certificate-Application-Policy',
        'msPKI-Certificate-Policy',
        'nTSecurityDescriptor'
    )

    $results = Search-LdapObjects -LdapPath $ldapPath -Filter '(objectclass=pKICertificateTemplate)' -Properties $properties
    $templates = New-Object System.Collections.Generic.List[object]

    foreach ($result in $results) {
        $dn = [string](Get-SearchValue -SearchResult $result -Name 'distinguishedname')
        $issuancePolicyOids = @(Get-SearchValues -SearchResult $result -Name 'mspki-certificate-policy' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $validityPeriodRaw = Get-SearchValue -SearchResult $result -Name 'pkiexpirationperiod'
        $renewalPeriodRaw = Get-SearchValue -SearchResult $result -Name 'pkioverlapperiod'
        $issuancePolicies = foreach ($oid in $issuancePolicyOids) {
            Get-EnterpriseOid -Oid $oid -ConfigurationPath $ConfigurationPath -Server $Server
        }

        $templateObject = [pscustomobject]@{
            DistinguishedName      = $dn
            Name                   = [string](Get-SearchValue -SearchResult $result -Name 'name')
            DomainName             = Get-DomainNameFromDn -DistinguishedName $dn
            Guid                   = Get-SearchGuid -SearchResult $result
            SchemaVersion          = ConvertTo-Int32 (Get-SearchValue -SearchResult $result -Name 'mspki-template-schema-version')
            DisplayName            = [string](Get-SearchValue -SearchResult $result -Name 'displayname')
            ValidityPeriod         = Convert-PkiPeriod -Bytes $validityPeriodRaw
            RenewalPeriod          = Convert-PkiPeriod -Bytes $renewalPeriodRaw
            Oid                    = [string](Get-SearchValue -SearchResult $result -Name 'mspki-cert-template-oid')
            CertificateNameFlag    = ConvertTo-UInt32FromSignedString (Get-SearchValue -SearchResult $result -Name 'mspki-certificate-name-flag')
            EnrollmentFlag         = ConvertTo-UInt32String (Get-SearchValue -SearchResult $result -Name 'mspki-enrollment-flag')
            ExtendedKeyUsage       = Get-SearchValues -SearchResult $result -Name 'pkiextendedkeyusage'
            ManagerApproval        = $false
            AuthorizedSignatures   = ConvertTo-Int32 (Get-SearchValue -SearchResult $result -Name 'mspki-ra-signature')
            RaApplicationPolicies  = Get-SearchValues -SearchResult $result -Name 'mspki-ra-application-policies'
            RaIssuancePolicies     = Get-SearchValues -SearchResult $result -Name 'mspki-ra-policies'
            ApplicationPolicies    = Get-SearchValues -SearchResult $result -Name 'mspki-certificate-application-policy'
            IssuancePolicies       = @($issuancePolicies | Where-Object { $null -ne $_ })
            SecurityDescriptor     = Get-SecurityDescriptor -SearchResult $result
            Vulnerabilities        = [ordered]@{}
        }

        $templateObject.ManagerApproval = Test-Flag -Value $templateObject.EnrollmentFlag -Flag $script:EnrollmentFlags.PEND_ALL_REQUESTS

        try {
            $templateObject.Vulnerabilities = Get-TemplateVulnerabilities -TemplateObject $templateObject -UserSids $UserSids
        }
        catch {
            Write-Host "[!] Warning: Unable to classify vulnerabilities for template '$($templateObject.DistinguishedName)': $($_.Exception.Message)"
            $templateObject.Vulnerabilities = [ordered]@{}
        }

        [void]$templates.Add($templateObject)
    }

    return @($templates.ToArray())
}

function Get-CertificateInfo {
    param(
        [byte[]]$Bytes,
        [string]$DistinguishedName,
        [int]$Index
    )

    if ($null -eq $Bytes) {
        return $null
    }

    try {
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$Bytes)
    }
    catch {
        Write-Host "[!] Warning: Unable to parse cACertificate value #$Index for '$DistinguishedName': $($_.Exception.Message)"
        return $null
    }
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
        $templates = Get-SearchValues -SearchResult $result -Name 'certificatetemplates'
        $certificates = if ($result.Properties.Contains('cacertificate')) {
            $certificateValues = $result.Properties['cacertificate']
            for ($i = 0; $i -lt $certificateValues.Count; $i++) {
                $certBytes = $certificateValues[$i]
                if ($null -ne $certBytes) {
                    Get-CertificateInfo -Bytes ([byte[]]$certBytes) -DistinguishedName $dn -Index ($i + 1)
                }
            }
        }

        $ca = [pscustomobject]@{
            DistinguishedName       = $dn
            Name                    = $name
            DomainName              = Get-DomainNameFromDn -DistinguishedName $dn
            Guid                    = Get-SearchGuid -SearchResult $result
            DnsHostname             = $dnsHostName
            FullName                = if ($dnsHostName) { "$dnsHostName\$name" } else { "\$name" }
            FlagsRaw                = ConvertTo-UInt32String (Get-SearchValue -SearchResult $result -Name 'flags')
            Certificates            = @($certificates | Where-Object { $null -ne $_ })
            SecurityDescriptor      = Get-SecurityDescriptor -SearchResult $result
            Templates               = $templates
            UserSpecifiedSan        = $null
            RpcRequestEncryption    = $null
            RpcRequestRestrictions  = @()
            DisabledExtensions      = @()
            ServerSecurityDescriptor = $null
            EnrollmentAgentSecurity = $null
            Vulnerabilities         = [ordered]@{}
        }

        try {
            Update-CaRuntimeInfo -CA $ca -UserSids $UserSids
        }
        catch {
            Write-Host "[!] Warning: Unable to complete runtime CA checks for '$($ca.DistinguishedName)': $($_.Exception.Message)"
        }

        [void]$cas.Add($ca)
    }

    return @($cas.ToArray())
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

function Update-CaRuntimeInfo {
    param(
        [pscustomobject]$CA,
        [string[]]$UserSids
    )

    try {
        $editFlags = ConvertTo-UInt32String (Get-RemoteRegistryValue -ComputerName $CA.DnsHostname -KeyName "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CA.Name)\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy" -ValueName 'EditFlags')
        $CA.UserSpecifiedSan = Get-FlagState -Flags $editFlags -Flag $script:EditFlags.ATTRIBUTE_SUBJECTALTNAME2
    }
    catch {
        Write-Host "[X] Could not connect to the HKLM hive - $($_.Exception.Message)"
        $CA.UserSpecifiedSan = $_.Exception.Message
    }

    try {
        $interfaceFlags = ConvertTo-UInt32String (Get-RemoteRegistryValue -ComputerName $CA.DnsHostname -KeyName "SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($CA.Name)" -ValueName 'InterfaceFlags')
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
        $vulnerabilities['6'] = 'The CA allows enrollees to specify SANs.'
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
            $vulnerabilities['7'] = 'The CA has insecure delegated security roles or permissions.'
        }
    }

    try {
        Initialize-EnumTemplatesHttpInterop
        $httpUrl = "http://$($CA.DnsHostname)/certsrv/"
        $httpsUrl = "https://$($CA.DnsHostname)/certsrv/"
        if ([CertifyPowerShell.EnumTemplatesHttpUtilQuiet]::AuthWithChannelBinding($httpUrl) -and [CertifyPowerShell.EnumTemplatesHttpUtilQuiet]::AuthWithoutChannelBinding($httpUrl)) {
            $vulnerabilities['8'] = 'The CA supports HTTP web enrollment without channel binding.'
        }
        elseif ([CertifyPowerShell.EnumTemplatesHttpUtilQuiet]::AuthWithChannelBinding($httpsUrl) -and [CertifyPowerShell.EnumTemplatesHttpUtilQuiet]::AuthWithoutChannelBinding($httpsUrl)) {
            $vulnerabilities['8'] = 'The CA supports HTTPS web enrollment without channel binding.'
        }
    }
    catch {
    }

    if ($CA.RpcRequestEncryption -eq 'Disabled') {
        $vulnerabilities['11'] = 'The CA does not enforce encryption on the ICertPassage RPC interface.'
    }

    if (@($CA.DisabledExtensions) -contains $script:CommonOids.NtdsCaSecurityExt) {
        $vulnerabilities['16'] = 'The CA has disabled the security extension.'
    }

    $CA.Vulnerabilities = $vulnerabilities
}

function Write-CertificateInfo {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)

    Write-Host "    Cert SubjectName              : $($Certificate.SubjectName.Name)"
    Write-Host "    Cert Thumbprint               : $($Certificate.Thumbprint)"
    Write-Host "    Cert Serial                   : $($Certificate.SerialNumber)"
    Write-Host "    Cert Start Date               : $($Certificate.NotBefore)"
    Write-Host "    Cert End Date                 : $($Certificate.NotAfter)"

    try {
        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        [void]$chain.Build($Certificate)
        $names = New-Object System.Collections.Generic.List[string]
        foreach ($element in $chain.ChainElements) {
            if ($null -ne $element.Certificate -and $null -ne $element.Certificate.SubjectName) {
                $names.Insert(0, $element.Certificate.SubjectName.Name.Replace(' ', ''))
            }
        }

        Write-Host "    Cert Chain                    : $($names -join ' -> ')"
    }
    catch {
        Write-Host "    Cert Chain                    : <unavailable: $($_.Exception.Message)>"
    }
}

function Convert-CaRightsToString {
    param([uint32]$Rights)

    $names = foreach ($entry in $script:CaRights.GetEnumerator()) {
        $flag = ConvertTo-UInt32String -Value $entry.Key
        if (Test-Flag -Value $Rights -Flag $flag) {
            [string]$entry.Value
        }
    }

    if (@($names).Count -eq 0) {
        return [string]$Rights
    }

    return (@($names) -join ', ')
}

function Write-AllPermissions {
    param([System.DirectoryServices.ActiveDirectorySecurity]$SecurityDescriptor)

    $ownerSid = $SecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    Write-Host ''
    Write-Host "      Owner: $(Get-UserSidString -Sid $ownerSid)"
    Write-Host ''
    Write-Host '      AccessControlType|PrincipalSid|PrincipalName|ActiveDirectoryRights|ObjectType|ObjectFlags|InheritanceType|InheritedObjectType|InheritanceFlags|IsInherited|PropagationFlags'

    foreach ($ace in $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $objectType = Get-AccessControlTypeFromGuid -Guid $ace.ObjectType.ToString()
        if ($null -eq $objectType) { $objectType = $ace.ObjectType.ToString() }
        $inheritedObjectType = Get-AccessControlTypeFromGuid -Guid $ace.InheritedObjectType.ToString()
        if ($null -eq $inheritedObjectType) { $inheritedObjectType = $ace.InheritedObjectType.ToString() }
        $principalName = Get-UserNameFromSid -Sid $ace.IdentityReference.Value

        Write-Host "      $($ace.AccessControlType)|$($ace.IdentityReference)|$principalName|$($ace.ActiveDirectoryRights)|$objectType|$($ace.ObjectFlags)|$($ace.InheritanceType)|$inheritedObjectType|$($ace.InheritanceFlags)|$($ace.IsInherited)|$($ace.PropagationFlags)"
    }
}

function Write-AllowPermissions {
    param(
        [System.DirectoryServices.ActiveDirectorySecurity]$SecurityDescriptor,
        [bool]$ShouldHideAdmins
    )

    $enrollmentPrincipals = New-Object System.Collections.Generic.List[string]
    $allExtendedPrincipals = New-Object System.Collections.Generic.List[string]
    $fullControlPrincipals = New-Object System.Collections.Generic.List[string]
    $writeOwnerPrincipals = New-Object System.Collections.Generic.List[string]
    $writeDaclPrincipals = New-Object System.Collections.Generic.List[string]
    $writePropertyPrincipals = New-Object System.Collections.Generic.List[string]

    foreach ($ace in $SecurityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        $sid = $ace.IdentityReference.Value
        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or ($ShouldHideAdmins -and (Test-IsAdminSid -Sid $sid))) {
            continue
        }

        if ($ace.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) {
            switch ($ace.ObjectType.ToString()) {
                '0e10c968-78fb-11d2-90d4-00c04f79dc55' { [void]$enrollmentPrincipals.Add((Get-UserSidString -Sid $sid)) }
                '00000000-0000-0000-0000-000000000000' { [void]$allExtendedPrincipals.Add((Get-UserSidString -Sid $sid)) }
            }
        }

        if ($ace.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) { [void]$fullControlPrincipals.Add((Get-UserSidString -Sid $sid)) }
        if ($ace.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) { [void]$writeOwnerPrincipals.Add((Get-UserSidString -Sid $sid)) }
        if ($ace.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) { [void]$writeDaclPrincipals.Add((Get-UserSidString -Sid $sid)) }
        if ($ace.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -and $ace.ObjectType.ToString() -eq '00000000-0000-0000-0000-000000000000') {
            [void]$writePropertyPrincipals.Add((Get-UserSidString -Sid $sid))
        }
    }

    $joinSep = "`n                                      "
    Write-Host '      Enrollment Permissions'
    if ($enrollmentPrincipals.Count -gt 0) { Write-Host "        Enrollment Rights           : $(@($enrollmentPrincipals.ToArray() | Sort-Object) -join $joinSep)" }
    if ($allExtendedPrincipals.Count -gt 0) { Write-Host "        All Extended Rights         : $(@($allExtendedPrincipals.ToArray() | Sort-Object) -join $joinSep)" }

    Write-Host '      Object Control Permissions'
    $ownerSid = $SecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not $ShouldHideAdmins -or -not (Test-IsAdminSid -Sid $ownerSid)) {
        Write-Host "        Owner                       : $(Get-UserSidString -Sid $ownerSid)"
    }

    if ($fullControlPrincipals.Count -gt 0) { Write-Host "        Full Control                : $(@($fullControlPrincipals.ToArray() | Sort-Object) -join $joinSep)" }
    if ($writeOwnerPrincipals.Count -gt 0) { Write-Host "        Write Owner                 : $(@($writeOwnerPrincipals.ToArray() | Sort-Object) -join $joinSep)" }
    if ($writeDaclPrincipals.Count -gt 0) { Write-Host "        Write Dacl                  : $(@($writeDaclPrincipals.ToArray() | Sort-Object) -join $joinSep)" }
    if ($writePropertyPrincipals.Count -gt 0) { Write-Host "        Write Property              : $(@($writePropertyPrincipals.ToArray() | Sort-Object) -join $joinSep)" }
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
        foreach ($key in @($CA.Vulnerabilities.Keys | Sort-Object { [int]$_ })) {
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
                try {
                    $entry = ConvertTo-EnrollmentAgentRestriction -Ace $ace
                }
                catch {
                    Write-Host "      [!] Unable to parse enrollment agent restriction ACE: $($_.Exception.Message)"
                    continue
                }

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

function ConvertTo-EnrollmentAgentRestriction {
    param([System.Security.AccessControl.CommonAce]$Ace)

    $bytes = $Ace.GetOpaque()
    if ($null -eq $bytes -or $bytes.Length -lt 4) {
        throw 'Enrollment agent restriction ACE has no opaque payload.'
    }

    $index = 0
    $sidCount = [BitConverter]::ToUInt32($bytes, $index)
    $index += 4

    $targets = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $sidCount; $i++) {
        if ($index -ge $bytes.Length) {
            throw 'Enrollment agent restriction ACE ended before all target SIDs were parsed.'
        }

        $sid = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList ($bytes, $index)
        [void]$targets.Add($sid.ToString())
        $index += $sid.BinaryLength
    }

    $templateName = '<All>'
    if ($index -lt ($bytes.Length - 2)) {
        $templateName = [Text.Encoding]::Unicode.GetString($bytes, $index, ($bytes.Length - $index - 2)).Replace("`0", '')
    }

    return [pscustomobject]@{
        Agent   = $Ace.SecurityIdentifier.ToString()
        Template = $templateName
        Targets  = @($targets.ToArray())
    }
}

function Write-CertificateTemplateInfo {
    param(
        [object[]]$CAs,
        [pscustomobject]$TemplateObject,
        [bool]$ShouldHideAdmins,
        [bool]$ShouldShowAllPermissions
    )

    Write-Host ''
    Write-Host "    Template Name                         : $($TemplateObject.Name)"
    Write-Host "    Enabled                               : $(@($CAs).Count -gt 0)"

    if (@($CAs).Count -gt 0) {
        Write-Host "    Publishing CAs                        : $((@($CAs) | ForEach-Object { $_.FullName }) -join "`n                                            ")"
    }

    Write-Host "    Schema Version                        : $($TemplateObject.SchemaVersion)"
    Write-Host "    Validity Period                       : $($TemplateObject.ValidityPeriod)"
    Write-Host "    Renewal Period                        : $($TemplateObject.RenewalPeriod)"
    Write-Host "    Certificate Name Flag                 : $(ConvertTo-FlagString -Value $TemplateObject.CertificateNameFlag -Map $script:NameFlags)"
    Write-Host "    Enrollment Flag                       : $(ConvertTo-FlagString -Value $TemplateObject.EnrollmentFlag -Map $script:EnrollmentFlags)"
    Write-Host "    Manager Approval Required             : $($TemplateObject.ManagerApproval)"
    Write-Host "    Authorized Signatures Required        : $($TemplateObject.AuthorizedSignatures)"

    if ($null -ne $TemplateObject.RaApplicationPolicies -and @($TemplateObject.RaApplicationPolicies).Count -gt 0) {
        Write-Host "    Required Application Policies         : $((@($TemplateObject.RaApplicationPolicies) | ForEach-Object { Get-FriendlyOid -Oid $_ } | Sort-Object) -join ', ')"
    }

    if ($null -ne $TemplateObject.RaIssuancePolicies -and @($TemplateObject.RaIssuancePolicies).Count -gt 0) {
        Write-Host "    Required Issuance Policies            : $((@($TemplateObject.RaIssuancePolicies) | ForEach-Object { Get-FriendlyOid -Oid $_ } | Sort-Object) -join ', ')"
    }

    if ($null -eq $TemplateObject.ExtendedKeyUsage) {
        Write-Host '    Extended Key Usage                    : <null>'
    }
    else {
        Write-Host "    Extended Key Usage                    : $((@($TemplateObject.ExtendedKeyUsage) | ForEach-Object { Get-FriendlyOid -Oid $_ } | Sort-Object) -join ', ')"
    }

    if ($null -eq $TemplateObject.ApplicationPolicies) {
        Write-Host '    Certificate Application Policies      : <null>'
    }
    else {
        Write-Host "    Certificate Application Policies      : $((@($TemplateObject.ApplicationPolicies) | ForEach-Object { Get-FriendlyOid -Oid $_ } | Sort-Object) -join ', ')"
    }

    if ($null -ne $TemplateObject.IssuancePolicies -and @($TemplateObject.IssuancePolicies).Count -gt 0) {
        $policyText = @($TemplateObject.IssuancePolicies | ForEach-Object {
            if ($_.GroupLink) {
                "$($_.DisplayName) (linked to group '$($_.GroupLink)')"
            }
            else {
                "$($_.DisplayName) (no linked groups)"
            }
        } | Sort-Object)
        Write-Host "    Certificate Issuance Policies         : $($policyText -join "`n                                            ")"
    }

    if ($TemplateObject.Vulnerabilities.Count -gt 0) {
        Write-Host '    Vulnerabilities'
        foreach ($key in @($TemplateObject.Vulnerabilities.Keys | Sort-Object { [int]$_ })) {
            Write-Host ("      {0,-35} : {1}" -f "ESC$key", $TemplateObject.Vulnerabilities[$key])
        }
    }

    Write-Host '    Permissions'

    if ($null -eq $TemplateObject.SecurityDescriptor) {
        Write-Host '      Security descriptor is null'
    }
    elseif ($ShouldShowAllPermissions) {
        Write-AllPermissions -SecurityDescriptor $TemplateObject.SecurityDescriptor
    }
    else {
        Write-AllowPermissions -SecurityDescriptor $TemplateObject.SecurityDescriptor -ShouldHideAdmins $ShouldHideAdmins
    }
}

function Invoke-EnumTemplates {
    Write-Host '[*] Action: Find certificate templates'

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

    if (-not [string]::IsNullOrWhiteSpace($CAName)) {
        Write-Host "[*] Restricting to CA name : $CAName"
    }

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

    $cas = @(Get-EnterpriseCAs -ConfigurationPath $configurationPath -Server $LdapServer -AuthorityName $CAName -UserSids $userSids)
    $templates = @(Get-CertificateTemplates -ConfigurationPath $configurationPath -Server $LdapServer -UserSids $userSids)

    if ($cas.Count -eq 0) {
        Write-Host '[!] Could not identify any enterprise certificate authorities.'
        return
    }

    if ($templates.Count -eq 0) {
        Write-Host '[!] Could not identify any certificate templates.'
        return
    }

    $validTemplates = New-Object System.Collections.Generic.List[object]
    foreach ($templateObject in $templates) {
        if ($null -eq $templateObject.Name) {
            Write-Host "[!] Warning: Unable to get the name of the template '$($templateObject.DistinguishedName)'."
        }
        elseif ($null -eq $templateObject.SecurityDescriptor) {
            Write-Host "[!] Warning: Unable to get the security descriptor for the template '$($templateObject.DistinguishedName)'."
        }
        else {
            [void]$validTemplates.Add($templateObject)
        }
    }

    $validCas = New-Object System.Collections.Generic.List[object]
    foreach ($ca in $cas) {
        Write-Host ''
        Write-Host "[*] Listing info about the enterprise certificate authority '$($ca.Name)'"
        Write-Host ''
        Write-EnterpriseCaInfo -CA $ca -ShouldHideAdmins $HideAdmins.IsPresent -ShouldShowAllPermissions $ShowAllPermissions.IsPresent

        if ($null -eq $ca.Templates) {
            Write-Host "[!] Warning: Unable to get a list of published certificate templates on certificate authority '$($ca.DistinguishedName)'."
        }
        else {
            [void]$validCas.Add($ca)
            $unreadableTemplates = @($ca.Templates | Where-Object { $name = $_; -not @($validTemplates.ToArray() | Where-Object { $_.Name -eq $name }).Count })

            if ($unreadableTemplates.Count -gt 0) {
                Write-Host "[!] The enterprise certificate authority '$($ca.Name)' publishes the following unreadable certificate templates:"
                Write-Host ''
                Write-Host "    $($unreadableTemplates -join "`n    ")"
                Write-Host ''
            }
        }
    }

    $filteredTemplates = @($validTemplates.ToArray())

    if (-not [string]::IsNullOrWhiteSpace($Template)) {
        $filteredTemplates = @($filteredTemplates | Where-Object { $_.Name -eq $Template })
    }

    if ($FilterManagerApproval) {
        $filteredTemplates = @($filteredTemplates | Where-Object { Test-Flag -Value $_.EnrollmentFlag -Flag $script:EnrollmentFlags.PEND_ALL_REQUESTS })
    }

    if ($FilterRequestAgent) {
        $filteredTemplates = @($filteredTemplates | Where-Object {
            $_.SchemaVersion -eq 1 -or ($_.SchemaVersion -ge 2 -and $null -ne $_.RaApplicationPolicies -and @($_.RaApplicationPolicies) -contains $script:CommonOids.CertificateRequestAgent)
        })
    }

    if ($FilterClientAuth) {
        $authOids = @($script:CommonOids.ClientAuthentication, $script:CommonOids.PKINITClientAuthentication, $script:CommonOids.SmartcardLogon, $script:CommonOids.AnyPurpose)
        $filteredTemplates = @($filteredTemplates | Where-Object {
            $null -eq $_.ExtendedKeyUsage -or @($_.ExtendedKeyUsage | Where-Object { $authOids -contains $_ }).Count -gt 0
        })
    }

    if ($FilterEnrolleeSuppliesSubject) {
        $filteredTemplates = @($filteredTemplates | Where-Object { Test-Flag -Value $_.CertificateNameFlag -Flag $script:NameFlags.ENROLLEE_SUPPLIES_SUBJECT })
    }

    if ($FilterVulnerable) {
        $filteredTemplates = @($filteredTemplates | Where-Object { $_.Vulnerabilities.Count -gt 0 })
    }

    if ($FilterEnabled) {
        $filteredTemplates = @($filteredTemplates | Where-Object {
            $templateName = $_.Name
            @($validCas.ToArray() | Where-Object { $null -ne $_.Templates -and @($_.Templates) -contains $templateName }).Count -gt 0
        })
    }

    if ($filteredTemplates.Count -eq 0) {
        Write-Host '[+] No certificates templates found with the current filter parameters.'
        return
    }

    Write-Host '[*] Certificate templates found using the current filter parameters:'

    foreach ($templateObject in $filteredTemplates) {
        $enabledCas = @($validCas.ToArray() | Where-Object { $null -ne $_.Templates -and @($_.Templates) -contains $templateObject.Name })
        Write-CertificateTemplateInfo -CAs $enabledCas -TemplateObject $templateObject -ShouldHideAdmins $HideAdmins.IsPresent -ShouldShowAllPermissions $ShowAllPermissions.IsPresent
    }
}

if ([string]::IsNullOrWhiteSpace($OutFile)) {
    try {
        Invoke-EnumTemplates
    }
    catch {
        Write-Host "[X] Unhandled enum-templates error: $($_.Exception.Message)"
        if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
            Write-Host $_.InvocationInfo.PositionMessage
        }
        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace
        }
    }
}
else {
    $dir = Split-Path -Path $OutFile -Parent
    if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $transcriptStarted = $false
    try {
        Start-Transcript -Path $OutFile -Force | Out-Null
        $transcriptStarted = $true
        Invoke-EnumTemplates
    }
    catch {
        Write-Host "[X] Unhandled enum-templates error: $($_.Exception.Message)"
        if ($_.InvocationInfo -and $_.InvocationInfo.PositionMessage) {
            Write-Host $_.InvocationInfo.PositionMessage
        }
        if ($_.ScriptStackTrace) {
            Write-Host $_.ScriptStackTrace
        }
    }
    finally {
        if ($transcriptStarted) {
            Stop-Transcript | Out-Null
        }
    }
}
