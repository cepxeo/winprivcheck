[CmdletBinding()]
param(
    [Alias('CA')]
    [string]$CAName,

    [Alias('TemplateName')]
    [string]$Template,

    [Alias('SubjectName')]
    [string]$Subject,

    [string[]]$Upn,
    [string[]]$Dns,
    [string[]]$Email,

    [Alias('SubjectAltNameSid')]
    [string]$SidUrl,

    [Alias('SidExtension')]
    [string]$Sid,

    [Alias('ApplicationPolicies')]
    [string[]]$ApplicationPolicy,

    [int]$KeySize = 2048,

    [Alias('Machine')]
    [switch]$MachineContext,

    [switch]$OutputPem,
    [switch]$OutputCSR,
    [switch]$Install,

    [string]$OutFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module "$PSScriptRoot/Certify.Defensive.Common.psm1" -Force

$script:RequestBoundParameters = @{} + $PSBoundParameters
$script:ContextUser = 1
$script:ContextMachine = 2
$script:EncodingBase64 = 1
$script:KeySpecSignature = 2
$script:KeyUsageAllowAll = 0x00ffffff
$script:ExportAllow = 1
$script:X500NameNone = 0
$script:X500NameSemicolon = 0x40000000
$script:InstallAllowUntrustedRoot = 4
$script:CR_IN_BASE64 = 0x1
$script:CR_IN_FORMATANY = 0
$script:CR_DISP_ISSUED = 0x3
$script:CR_DISP_UNDER_SUBMISSION = 0x5
$script:CR_OUT_BASE64 = 0x1

function Initialize-CertifyRequestInterop {
    if ('CertifyPowerShell.RequestInterop' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

namespace CertifyPowerShell
{
    public enum CertAltNameType
    {
        OtherName = 1,
        RFC822 = 2,
        DNS = 3,
        X400Address = 4,
        DirectoryName = 5,
        EdiPartyName = 6,
        URL = 7,
        IPAddress = 8,
        RegisteredId = 9
    }

    [Flags]
    public enum CryptEncodeFlags
    {
        CRYPT_ENCODE_ALLOC_FLAG = 0x8000,
        CRYPT_ENCODE_ENABLE_PUNYCODE_FLAG = 0x20000,
        CRYPT_UNICODE_NAME_ENCODE_DISABLE_CHECK_TYPE_FLAG = 0x40000000,
        CRYPT_UNICODE_NAME_ENCODE_ENABLE_T61_UNICODE_FLAG = unchecked((int)0x80000000),
        CRYPT_UNICODE_NAME_ENCODE_ENABLE_UTF8_UNICODE_FLAG = 0x20000000,
        CRYPT_UNICODE_NAME_ENCODE_FORCE_UTF8_UNICODE_FLAG = 0x10000000
    }

    [Flags]
    public enum CertEncodingType : int
    {
        X509 = 0x1,
        PKCS7 = 0x10000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_ALT_NAME_INFO
    {
        public int cAltEntry;
        public IntPtr rgAltEntry;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CERT_ALT_NAME_ENTRY
    {
        public CertAltNameType dwAltNameChoice;
        public CERT_ALT_NAME_ENTRY_UNION Value;
    }

    [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Unicode)]
    public struct CERT_ALT_NAME_ENTRY_UNION
    {
        [FieldOffset(0)]
        public IntPtr pOtherName;
        [FieldOffset(0)]
        public IntPtr pwszRfc822Name;
        [FieldOffset(0)]
        public IntPtr pwszDNSName;
        [FieldOffset(0)]
        public CRYPT_BLOB DirectoryName;
        [FieldOffset(0)]
        public IntPtr pwszURL;
        [FieldOffset(0)]
        public CRYPT_BLOB IPAddress;
        [FieldOffset(0)]
        public IntPtr pszRegisteredID;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_OTHER_NAME
    {
        [MarshalAs(UnmanagedType.LPStr)]
        public string pszObjId;
        [MarshalAs(UnmanagedType.Struct)]
        public CRYPT_BLOB Value;
    }

    public static class RequestInterop
    {
        [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptEncodeObjectEx(
            CertEncodingType dwCertEncodingType,
            [MarshalAs(UnmanagedType.LPStr)]
            string lpszStructType,
            IntPtr pvStructInfo,
            CryptEncodeFlags dwFlags,
            IntPtr pEncodePara,
            IntPtr pvEncoded,
            [MarshalAs(UnmanagedType.I4)]
            ref int pcbEncoded
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool RevertToSelf();

        public const string szOID_SUBJECT_ALT_NAME2 = "2.5.29.17";

        public static string CurrentIdentityName()
        {
            return WindowsIdentity.GetCurrent().Name;
        }

        public static bool IsSystem()
        {
            return WindowsIdentity.GetCurrent().IsSystem;
        }

        public static bool IsHighIntegrity()
        {
            var principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        public static void ImpersonateWinlogon()
        {
            foreach (var process in Process.GetProcessesByName("winlogon"))
            {
                IntPtr hProcToken = IntPtr.Zero;

                try
                {
                    if (!OpenProcessToken(process.Handle, 0x0002, out hProcToken))
                        continue;

                    IntPtr hDupToken = IntPtr.Zero;
                    try
                    {
                        if (!DuplicateToken(hProcToken, 2, ref hDupToken))
                            continue;

                        if (!ImpersonateLoggedOnUser(hDupToken))
                            continue;

                        if (!IsSystem())
                            throw new InvalidOperationException("Impersonation succeeded, but the current thread is not SYSTEM.");

                        return;
                    }
                    finally
                    {
                        if (hDupToken != IntPtr.Zero)
                            CloseHandle(hDupToken);
                    }
                }
                finally
                {
                    if (hProcToken != IntPtr.Zero)
                        CloseHandle(hProcToken);
                }
            }

            throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to impersonate a winlogon SYSTEM token.");
        }

        public static byte[] EncodeSidExtension(string sid)
        {
            if (sid == null)
                throw new ArgumentNullException("sid");

            var sidOid = "1.3.6.1.4.1.311.25.2.1";
            var unmanagedSidString = IntPtr.Zero;
            var unmanagedpOtherName = IntPtr.Zero;
            var unmanagedAltNameEntry = IntPtr.Zero;
            var unmanagedAltNameInfo = IntPtr.Zero;
            var outputPtr = IntPtr.Zero;

            try
            {
                var sidLength = sid.Length;

                if (sidLength > 127)
                    throw new ArgumentOutOfRangeException("sid", "String representation of the provided security identifier must not exceed 127 characters.");

                var octetString = new byte[sidLength + 2];
                octetString[0] = 0x04;
                octetString[1] = (byte)sidLength;
                Array.Copy(Encoding.ASCII.GetBytes(sid), 0, octetString, 2, sidLength);

                unmanagedSidString = Marshal.AllocHGlobal(octetString.Length);
                Marshal.Copy(octetString, 0, unmanagedSidString, octetString.Length);

                var otherName = new CERT_OTHER_NAME();
                otherName.pszObjId = sidOid;
                otherName.Value = new CRYPT_BLOB();
                otherName.Value.cbData = sidLength + 2;
                otherName.Value.pbData = unmanagedSidString;

                unmanagedpOtherName = Marshal.AllocHGlobal(Marshal.SizeOf(otherName));
                Marshal.StructureToPtr(otherName, unmanagedpOtherName, false);

                var altName = new CERT_ALT_NAME_ENTRY_UNION();
                altName.pOtherName = unmanagedpOtherName;

                var altNameEntry = new CERT_ALT_NAME_ENTRY();
                altNameEntry.dwAltNameChoice = CertAltNameType.OtherName;
                altNameEntry.Value = altName;

                unmanagedAltNameEntry = Marshal.AllocHGlobal(Marshal.SizeOf(altNameEntry));
                Marshal.StructureToPtr(altNameEntry, unmanagedAltNameEntry, false);

                var altNames = new CERT_ALT_NAME_INFO();
                altNames.cAltEntry = 1;
                altNames.rgAltEntry = unmanagedAltNameEntry;

                unmanagedAltNameInfo = Marshal.AllocHGlobal(Marshal.SizeOf(altNames));
                Marshal.StructureToPtr(altNames, unmanagedAltNameInfo, false);

                int resultSize = 0;
                CryptEncodeObjectEx(CertEncodingType.X509, szOID_SUBJECT_ALT_NAME2, unmanagedAltNameInfo, 0, IntPtr.Zero, outputPtr, ref resultSize);

                if (resultSize > 1)
                {
                    outputPtr = Marshal.AllocHGlobal(resultSize);
                    if (!CryptEncodeObjectEx(CertEncodingType.X509, szOID_SUBJECT_ALT_NAME2, unmanagedAltNameInfo, 0, IntPtr.Zero, outputPtr, ref resultSize))
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    var output = new byte[resultSize];
                    Marshal.Copy(outputPtr, output, 0, resultSize);
                    return output;
                }

                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally
            {
                if (unmanagedSidString != IntPtr.Zero)
                    Marshal.FreeHGlobal(unmanagedSidString);
                if (unmanagedpOtherName != IntPtr.Zero)
                    Marshal.FreeHGlobal(unmanagedpOtherName);
                if (unmanagedAltNameEntry != IntPtr.Zero)
                    Marshal.FreeHGlobal(unmanagedAltNameEntry);
                if (unmanagedAltNameInfo != IntPtr.Zero)
                    Marshal.FreeHGlobal(unmanagedAltNameInfo);
                if (outputPtr != IntPtr.Zero)
                    Marshal.FreeHGlobal(outputPtr);
            }
        }

        public static string ConvertCspBlobToPem(string privateKeyBlobBase64)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(privateKeyBlobBase64));
                return ExportPrivateKey(rsa);
            }
        }

        public static byte[] MakePfx(string certificatePemOrBase64, string privateKeyBlobBase64)
        {
            var certBytes = Convert.FromBase64String(RemovePemArmor(certificatePemOrBase64));
            var cert = new X509Certificate2(certBytes);

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(Convert.FromBase64String(privateKeyBlobBase64));
                var withKey = System.Security.Cryptography.X509Certificates.RSACertificateExtensions.CopyWithPrivateKey(cert, rsa);
                return withKey.Export(X509ContentType.Pkcs12, (string)null);
            }
        }

        private static string RemovePemArmor(string input)
        {
            var sb = new StringBuilder();

            using (var reader = new StringReader(input))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    if (line.StartsWith("-----", StringComparison.Ordinal))
                        continue;

                    if (line.Trim().Length > 0)
                        sb.Append(line.Trim());
                }
            }

            return sb.ToString();
        }

        private static string ExportPrivateKey(RSACryptoServiceProvider csp)
        {
            if (csp.PublicOnly)
                throw new ArgumentException("CSP does not contain a private key", "csp");

            using (var outputStream = new StringWriter())
            {
                var parameters = csp.ExportParameters(true);

                using (var stream = new MemoryStream())
                {
                    using (var writer = new BinaryWriter(stream))
                    {
                        writer.Write((byte)0x30);

                        using (var innerStream = new MemoryStream())
                        {
                            using (var innerWriter = new BinaryWriter(innerStream))
                            {
                                EncodeIntegerBigEndian(innerWriter, new byte[] { 0x00 }, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.Modulus, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.Exponent, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.D, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.P, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.Q, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.DP, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.DQ, true);
                                EncodeIntegerBigEndian(innerWriter, parameters.InverseQ, true);

                                EncodeLength(writer, (int)innerStream.Length);
                                innerStream.WriteTo(stream);
                            }
                        }

                        var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();
                        outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----");

                        for (var i = 0; i < base64.Length; i += 64)
                            outputStream.WriteLine(base64, i, Math.Min(64, base64.Length - i));

                        outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
                        return outputStream.ToString();
                    }
                }
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0)
                throw new ArgumentOutOfRangeException("length", "Length must be non-negative");

            if (length < 0x80)
            {
                stream.Write((byte)length);
                return;
            }

            int bytesRequired = 0;

            for (var i = length; i > 0; i >>= 8)
                bytesRequired++;

            stream.Write((byte)(bytesRequired | 0x80));

            for (var i = bytesRequired - 1; i >= 0; i--)
                stream.Write((byte)(length >> (8 * i) & 0xff));
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned)
        {
            stream.Write((byte)0x02);

            var prefixZeros = 0;

            for (var i = 0; i < value.Length && value[i] == 0; i++)
                prefixZeros++;

            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
                return;
            }

            if (forceUnsigned && value[prefixZeros] > 0x7f)
            {
                EncodeLength(stream, value.Length - prefixZeros + 1);
                stream.Write((byte)0);
            }
            else
            {
                EncodeLength(stream, value.Length - prefixZeros);
            }

            for (var i = prefixZeros; i < value.Length; i++)
                stream.Write(value[i]);
        }
    }
}
'@
}

function Test-IsWindows {
    return ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
}

function Expand-CommaSeparatedEnv {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return @()
    }

    return @(($Value.Split(',') | ForEach-Object { $_.Trim() }) | Where-Object { $_ })
}

function Resolve-OptionalStringCollection {
    param(
        [string[]]$ParameterValue,
        [string[]]$EnvNames
    )

    $fromParam = @(@($ParameterValue) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    if ($fromParam.Count -gt 0) {
        return $fromParam
    }

    foreach ($envName in $EnvNames) {
        $expanded = Expand-CommaSeparatedEnv -Value ([Environment]::GetEnvironmentVariable($envName))
        if ($expanded.Count -gt 0) {
            return $expanded
        }
    }

    return @()
}

function Resolve-EnvSwitch {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$WasBound,

        [Parameter(Mandatory = $true)]
        [switch]$ParameterValue,

        [Parameter(Mandatory = $true)]
        [string[]]$EnvNames
    )

    if ($WasBound) {
        return $ParameterValue.IsPresent
    }

    $envValue = Resolve-CertifyDefensiveEnvString -ParameterValue $null -EnvironmentVariableNames $EnvNames
    return ($envValue -match '^(?i:1|true|yes)$')
}

function Get-CurrentIdentityName {
    try {
        Initialize-CertifyRequestInterop
        return [CertifyPowerShell.RequestInterop]::CurrentIdentityName()
    }
    catch {
        if (-not [string]::IsNullOrWhiteSpace($env:USERNAME)) {
            return $env:USERNAME
        }

        if (-not [string]::IsNullOrWhiteSpace($env:USER)) {
            return $env:USER
        }

        return '(unavailable)'
    }
}

function Get-CurrentUserDistinguishedName {
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $dn = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).DistinguishedName
        if (-not [string]::IsNullOrWhiteSpace($dn)) {
            return $dn.Replace(',', ', ')
        }
    }
    catch {
    }

    return $null
}

function Get-CurrentComputerSubject {
    try {
        $hostEntry = [System.Net.Dns]::GetHostEntry('')
        $hostName = ($hostEntry | Select-Object -First 1 -ExpandProperty HostName)
        if (-not [string]::IsNullOrWhiteSpace($hostName)) {
            return "CN=$($hostName.Trim())"
        }
    }
    catch {
    }

    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {
        return "CN=$($env:COMPUTERNAME.Trim())"
    }

    return 'CN=localhost'
}

function Resolve-SubjectName {
    param(
        [string]$SubjectProvided,
        [bool]$UseMachineContext
    )

    if (-not [string]::IsNullOrWhiteSpace($SubjectProvided)) {
        return $SubjectProvided.Trim()
    }

    if ($UseMachineContext) {
        Write-Host "[*] No subject name specified, using current machine as subject"
        return Get-CurrentComputerSubject
    }

    try {
        Initialize-CertifyRequestInterop
        if ([CertifyPowerShell.RequestInterop]::IsSystem()) {
            Write-Host "[!] WARNING: You are currently running as SYSTEM. You may want to use the '--machine' argument to use the machine account instead."
        }
    }
    catch {
    }

    $dn = Get-CurrentUserDistinguishedName
    Write-Host "[*] No subject name specified, using current context as subject."

    if (-not [string]::IsNullOrWhiteSpace($dn)) {
        return $dn
    }

    Write-Host "[*] Current context did not contain a subject. Using default 'CN=User'."
    return 'CN=User'
}

function New-CertifyComObject {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProgId
    )

    try {
        return New-Object -ComObject $ProgId
    }
    catch {
        throw "Unable to create COM object '$ProgId'. This request implementation must run on Windows with the Certificate Enrollment and Certificate Authority client COM components available. $($_.Exception.Message)"
    }
}

function New-SubjectAlternativeNames {
    param(
        [string[]]$ResolvedUpns,
        [string[]]$ResolvedDns,
        [string[]]$ResolvedEmails,
        [string]$ResolvedSidUrl
    )

    $sans = New-Object System.Collections.Generic.List[object]

    foreach ($x in $ResolvedUpns) {
        $sans.Add([pscustomobject]@{ Type = 'Upn'; Value = $x }) | Out-Null
    }

    foreach ($x in $ResolvedDns) {
        $sans.Add([pscustomobject]@{ Type = 'Dns'; Value = $x }) | Out-Null
    }

    foreach ($x in $ResolvedEmails) {
        $sans.Add([pscustomobject]@{ Type = 'Email'; Value = $x }) | Out-Null
    }

    if (-not [string]::IsNullOrWhiteSpace($ResolvedSidUrl)) {
        $sans.Add([pscustomobject]@{ Type = 'Url'; Value = "tag:microsoft.com,2022-09-14:sid:$($ResolvedSidUrl.Trim())" }) | Out-Null
    }

    return @($sans.ToArray())
}

function Get-SanComType {
    param([string]$Type)

    switch ($Type) {
        'Upn' { return 11 }
        'Dns' { return 3 }
        'Email' { return 2 }
        'Url' { return 7 }
        default { throw "Unknown SAN type '$Type'." }
    }
}

function Get-SanAttributeName {
    param([string]$Type)

    switch ($Type) {
        'Upn' { return 'upn' }
        'Dns' { return 'Dns' }
        'Email' { return 'Email' }
        'Url' { return 'URL' }
        default { throw "Unknown SAN type '$Type'." }
    }
}

function New-TemplateNameExtension {
    param([string]$TemplateName)

    $templateExtension = New-CertifyComObject -ProgId 'X509Enrollment.CX509ExtensionTemplateName'
    $templateExtension.InitializeEncode($TemplateName)
    return $templateExtension
}

function New-SanExtension {
    param([object[]]$Sans)

    $altNames = New-CertifyComObject -ProgId 'X509Enrollment.CAlternativeNames'

    foreach ($san in $Sans) {
        $altName = New-CertifyComObject -ProgId 'X509Enrollment.CAlternativeName'
        $altName.InitializeFromString((Get-SanComType -Type $san.Type), $san.Value)
        $altNames.Add($altName)
    }

    $sanExtension = New-CertifyComObject -ProgId 'X509Enrollment.CX509ExtensionAlternativeNames'
    $sanExtension.InitializeEncode($altNames)
    return $sanExtension
}

function New-SanAttribute {
    param([object[]]$Sans)

    $parts = foreach ($san in $Sans) {
        "$(Get-SanAttributeName -Type $san.Type)=$($san.Value)"
    }

    $sanAttribute = New-CertifyComObject -ProgId 'X509Enrollment.CX509NameValuePair'
    $sanAttribute.Initialize('SAN', ($parts -join '&'))
    return $sanAttribute
}

function New-SidExtension {
    param([string]$SidValue)

    $oid = New-CertifyComObject -ProgId 'X509Enrollment.CObjectId'
    $oid.InitializeFromValue('1.3.6.1.4.1.311.25.2')

    $raw = [CertifyPowerShell.RequestInterop]::EncodeSidExtension($SidValue)
    $extension = New-CertifyComObject -ProgId 'X509Enrollment.CX509Extension'
    $extension.Initialize($oid, $script:EncodingBase64, [Convert]::ToBase64String($raw))
    return $extension
}

function New-ApplicationPolicyExtension {
    param([string[]]$Policies)

    $certificatePolicies = New-CertifyComObject -ProgId 'X509Enrollment.CCertificatePolicies'

    foreach ($policyOidValue in $Policies) {
        $policyOid = New-CertifyComObject -ProgId 'X509Enrollment.CObjectId'
        $policyOid.InitializeFromValue($policyOidValue)

        $policy = New-CertifyComObject -ProgId 'X509Enrollment.CCertificatePolicy'
        $policy.Initialize($policyOid)

        $certificatePolicies.Add($policy)
    }

    $extension = New-CertifyComObject -ProgId 'X509Enrollment.CX509ExtensionMSApplicationPolicies'
    $extension.InitializeEncode($certificatePolicies)
    return $extension
}

function New-CertificateRequestMessage {
    param(
        [string]$TemplateName,
        [string]$SubjectName,
        [object[]]$Sans,
        [string]$SidExtensionValue,
        [string[]]$Policies,
        [int]$EffectiveKeySize,
        [bool]$UseMachineContext
    )

    $cspInfo = New-CertifyComObject -ProgId 'X509Enrollment.CCspInformations'
    $cspInfo.AddAvailableCsps()

    $privateKey = New-CertifyComObject -ProgId 'X509Enrollment.CX509PrivateKey'
    $privateKey.Length = $EffectiveKeySize
    $privateKey.KeySpec = $script:KeySpecSignature
    $privateKey.KeyUsage = $script:KeyUsageAllowAll
    $privateKey.MachineContext = $UseMachineContext
    $privateKey.ExportPolicy = $script:ExportAllow
    $privateKey.CspInformations = $cspInfo
    $privateKey.Create()

    $privateKeyBlobBase64 = $privateKey.Export('PRIVATEBLOB', $script:EncodingBase64)
    $privateKeyPem = [CertifyPowerShell.RequestInterop]::ConvertCspBlobToPem($privateKeyBlobBase64)

    $pkcs10 = New-CertifyComObject -ProgId 'X509Enrollment.CX509CertificateRequestPkcs10'
    $context = if ($UseMachineContext) { $script:ContextMachine } else { $script:ContextUser }
    $pkcs10.InitializeFromPrivateKey($context, $privateKey, '')

    $pkcs10.X509Extensions.Add((New-TemplateNameExtension -TemplateName $TemplateName))

    $distinguishedName = New-CertifyComObject -ProgId 'X509Enrollment.CX500DistinguishedName'

    try {
        $distinguishedName.Encode($SubjectName, $script:X500NameNone)
    }
    catch {
        $distinguishedName.Encode($SubjectName, $script:X500NameSemicolon)
    }

    $pkcs10.Subject = $distinguishedName

    if ($null -ne $Sans -and $Sans.Count -gt 0) {
        $pkcs10.X509Extensions.Add((New-SanExtension -Sans $Sans))
        $pkcs10.NameValuePairs.Add((New-SanAttribute -Sans $Sans))
    }

    if (-not [string]::IsNullOrWhiteSpace($SidExtensionValue)) {
        $pkcs10.X509Extensions.Add((New-SidExtension -SidValue $SidExtensionValue.Trim()))
    }

    if ($null -ne $Policies -and $Policies.Count -gt 0) {
        $pkcs10.X509Extensions.Add((New-ApplicationPolicyExtension -Policies $Policies))
    }

    $enrollment = New-CertifyComObject -ProgId 'X509Enrollment.CX509Enrollment'
    $enrollment.InitializeFromRequest($pkcs10)
    $requestBase64 = $enrollment.CreateRequest($script:EncodingBase64)

    return [pscustomobject]@{
        RequestBase64        = $requestBase64
        PrivateKeyPem        = $privateKeyPem
        PrivateKeyBlobBase64 = $privateKeyBlobBase64
    }
}

function ConvertTo-SignedInt32 {
    param([uint32]$Value)

    return [BitConverter]::ToInt32([BitConverter]::GetBytes($Value), 0)
}

function Send-CertificateRequest {
    param(
        [string]$CertificateAuthority,
        [string]$Message
    )

    $certRequest = New-CertifyComObject -ProgId 'CertificateAuthority.Request'
    $disposition = $certRequest.Submit(($script:CR_IN_BASE64 -bor $script:CR_IN_FORMATANY), $Message, '', $CertificateAuthority)

    switch ($disposition) {
        $script:CR_DISP_ISSUED {
            Write-Host "[*] CA Response             : The certificate has been issued."
        }
        $script:CR_DISP_UNDER_SUBMISSION {
            Write-Host "[*] CA Response             : The certificate is still pending."
        }
        default {
            $lastStatus = [uint32]$certRequest.GetLastStatus()
            Write-Host "[!] CA Response             : The submission failed: $($certRequest.GetDispositionMessage())"

            $exception = [Runtime.InteropServices.Marshal]::GetExceptionForHR((ConvertTo-SignedInt32 -Value $lastStatus))
            if ($null -ne $exception -and -not [string]::IsNullOrWhiteSpace($exception.Message)) {
                Write-Host "[!] Last status             : $($exception.Message)"
            }
            else {
                Write-Host ("[!] Last status             : 0x{0:X}" -f $lastStatus)
            }
        }
    }

    return [int]$certRequest.GetRequestId()
}

function ConvertTo-CertificatePem {
    param([string]$CertificateBase64)

    return "-----BEGIN CERTIFICATE-----`r`n$CertificateBase64`r`n-----END CERTIFICATE-----`r`n"
}

function Receive-Certificate {
    param(
        [string]$CertificateAuthority,
        [int]$RequestId
    )

    $certRequest = New-CertifyComObject -ProgId 'CertificateAuthority.Request'
    $disposition = $certRequest.RetrievePending($RequestId, $CertificateAuthority)

    if ($disposition -ne $script:CR_DISP_ISSUED) {
        throw "certificate has not yet been issued! (disposition: $disposition)"
    }

    return $certRequest.GetCertificate($script:CR_OUT_BASE64)
}

function Receive-AndInstallCertificate {
    param(
        [string]$CertificateAuthority,
        [int]$RequestId
    )

    $certificateBase64 = Receive-Certificate -CertificateAuthority $CertificateAuthority -RequestId $RequestId

    $enrollment = New-CertifyComObject -ProgId 'X509Enrollment.CX509Enrollment'
    $enrollment.Initialize($script:ContextUser)
    $enrollment.InstallResponse($script:InstallAllowUntrustedRoot, $certificateBase64, $script:EncodingBase64, $null)
    Write-Host "[*] Certificate installed!"

    return $certificateBase64
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

function Invoke-CertRequest {
    $CANameResolved = Resolve-CertifyDefensiveEnvString -ParameterValue $CAName -EnvironmentVariableNames @('CERTIFY_CA_NAME')
    $TemplateResolved = Resolve-CertifyDefensiveEnvString -ParameterValue $Template -EnvironmentVariableNames @('CERTIFY_TEMPLATE')
    $SubjectResolved = Resolve-CertifyDefensiveEnvString -ParameterValue $Subject -EnvironmentVariableNames @('CERTIFY_SUBJECT')
    $SidUrlResolved = Resolve-CertifyDefensiveEnvString -ParameterValue $SidUrl -EnvironmentVariableNames @('CERTIFY_SID_URL')
    $SidResolved = Resolve-CertifyDefensiveEnvString -ParameterValue $Sid -EnvironmentVariableNames @('CERTIFY_SID_EXTENSION', 'CERTIFY_SID')

    $effectiveKeySize = $KeySize
    $keySizeEnv = Resolve-CertifyDefensiveEnvString -ParameterValue $null -EnvironmentVariableNames @('CERTIFY_KEY_SIZE')
    if (-not ($script:RequestBoundParameters.ContainsKey('KeySize'))) {
        [int]$parsedKeySize = 0
        if (-not [string]::IsNullOrWhiteSpace($keySizeEnv) -and [int]::TryParse($keySizeEnv, [ref]$parsedKeySize)) {
            $effectiveKeySize = $parsedKeySize
        }
    }

    $effectiveMachineContext = Resolve-EnvSwitch -WasBound ($script:RequestBoundParameters.ContainsKey('MachineContext')) -ParameterValue $MachineContext -EnvNames @('CERTIFY_MACHINE_CONTEXT', 'CERTIFY_MACHINE')
    $effectiveOutputPem = Resolve-EnvSwitch -WasBound ($script:RequestBoundParameters.ContainsKey('OutputPem')) -ParameterValue $OutputPem -EnvNames @('CERTIFY_OUTPUT_PEM')
    $effectiveOutputCSR = Resolve-EnvSwitch -WasBound ($script:RequestBoundParameters.ContainsKey('OutputCSR')) -ParameterValue $OutputCSR -EnvNames @('CERTIFY_OUTPUT_CSR')
    $effectiveInstall = Resolve-EnvSwitch -WasBound ($script:RequestBoundParameters.ContainsKey('Install')) -ParameterValue $Install -EnvNames @('CERTIFY_INSTALL')

    $resolvedUpns = @(Resolve-OptionalStringCollection $Upn @('CERTIFY_UPN', 'CERTIFY_SUBJECTALT_UPN'))
    $resolvedDns = @(Resolve-OptionalStringCollection $Dns @('CERTIFY_DNS', 'CERTIFY_SUBJECTALT_DNS'))
    $resolvedEmails = @(Resolve-OptionalStringCollection $Email @('CERTIFY_EMAIL', 'CERTIFY_SUBJECTALT_EMAIL'))

    $sanLegacy = Resolve-CertifyDefensiveEnvString -ParameterValue $null -EnvironmentVariableNames @('CERTIFY_SAN')
    if (-not [string]::IsNullOrWhiteSpace($sanLegacy) -and $resolvedDns.Count -eq 0 -and $resolvedUpns.Count -eq 0 -and $resolvedEmails.Count -eq 0 -and (@($Dns).Count -eq 0) -and (@($Upn).Count -eq 0) -and (@($Email).Count -eq 0)) {
        $resolvedDns = @($sanLegacy.Trim())
    }

    $resolvedPolicies = @(Resolve-OptionalStringCollection $ApplicationPolicy @('CERTIFY_APPLICATION_POLICY', 'CERTIFY_APPLICATION_POLICIES'))

    foreach ($policy in $resolvedPolicies) {
        if (-not [System.Text.RegularExpressions.Regex]::IsMatch($policy, '^\d+(\.\d+)*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            throw "A policy parameter is not of the format '<policy oid>'. Invalid: '$policy'."
        }
    }

    if ([string]::IsNullOrWhiteSpace($CANameResolved) -or [string]::IsNullOrWhiteSpace($TemplateResolved)) {
        throw "Certificate authority and template are required. Pass -CAName / -CA and -Template, or CERTIFY_CA_NAME and CERTIFY_TEMPLATE."
    }

    if ($CANameResolved -notmatch '\\') {
        throw "The 'certificate authority' parameter is not of the format 'SERVER\CA-NAME'. Value: '$CANameResolved'"
    }

    if ($effectiveKeySize -ne 512 -and $effectiveKeySize -ne 1024 -and $effectiveKeySize -ne 2048 -and $effectiveKeySize -ne 4096) {
        throw "The 'key size' parameter must be either 512, 1024, 2048 or 4096."
    }

    if (-not (Test-IsWindows)) {
        throw "The PowerShell request implementation uses Windows X509Enrollment and CertificateAuthority COM APIs and must run on Windows."
    }

    Initialize-CertifyRequestInterop

    Write-Host "[*] Action: Request a certificate"

    $didImpersonate = $false

    try {
        if ($effectiveMachineContext -and -not [CertifyPowerShell.RequestInterop]::IsSystem()) {
            Write-Host "[*] Elevating to SYSTEM context for machine cert request"

            if (-not [CertifyPowerShell.RequestInterop]::IsHighIntegrity()) {
                throw "Need to be in an elevated context for machine certificate requests."
            }

            [CertifyPowerShell.RequestInterop]::ImpersonateWinlogon()
            $didImpersonate = $true
        }

        Write-Host ''
        Write-Host "[*] Current user context    : $([CertifyPowerShell.RequestInterop]::CurrentIdentityName())"

        $subjectName = Resolve-SubjectName -SubjectProvided $SubjectResolved -UseMachineContext $effectiveMachineContext
        $sans = @(New-SubjectAlternativeNames -ResolvedUpns $resolvedUpns -ResolvedDns $resolvedDns -ResolvedEmails $resolvedEmails -ResolvedSidUrl $SidUrlResolved)

        Write-Host ''
        Write-Host "[*] Template                : $TemplateResolved"
        Write-Host "[*] Subject                 : $subjectName"

        if ($sans.Count -gt 0) {
            Write-Host "[*] Subject Alt Name(s)     : $(($sans | ForEach-Object { $_.Value }) -join ', ')"
        }

        if (-not [string]::IsNullOrWhiteSpace($SidResolved)) {
            Write-Host "[*] Sid Extension           : $SidResolved"
        }

        if ($resolvedPolicies.Count -gt 0) {
            Write-Host "[*] Application Policies    : $($resolvedPolicies -join ', ')"
        }

        $csr = New-CertificateRequestMessage -TemplateName $TemplateResolved -SubjectName $subjectName -Sans $sans -SidExtensionValue $SidResolved -Policies $resolvedPolicies -EffectiveKeySize $effectiveKeySize -UseMachineContext $effectiveMachineContext

        Write-Host ''
        Write-Host "[*] Certificate Authority   : $CANameResolved"

        if ($effectiveOutputCSR) {
            Write-Host ''
            Write-Host "[*] Generate Certificate Signing Request (CSR)"
            Write-Host "[+] Cert Signing Request    :"
            Write-Host $csr.RequestBase64
            Write-Host ''
            Write-Host "[+] Private Key           :"
            Write-Host $csr.PrivateKeyPem
            return
        }

        try {
            $requestId = Send-CertificateRequest -CertificateAuthority $CANameResolved -Message $csr.RequestBase64

            Write-Host "[*] Request ID              : $requestId"
            Write-Host ''

            Start-Sleep -Seconds 3

            if ($effectiveInstall) {
                $certificateBase64 = Receive-AndInstallCertificate -CertificateAuthority $CANameResolved -RequestId $requestId
            }
            else {
                $certificateBase64 = Receive-Certificate -CertificateAuthority $CANameResolved -RequestId $requestId
            }

            $certificatePem = ConvertTo-CertificatePem -CertificateBase64 $certificateBase64

            if ($effectiveOutputPem) {
                Write-Host "[*] Certificate (PEM)       :"
                Write-Host ''
                Write-Host -NoNewline $csr.PrivateKeyPem
                Write-Host -NoNewline $certificatePem
            }
            else {
                Write-Host "[*] Certificate (PFX)       :"
                Write-Host ''
                Write-Host ([Convert]::ToBase64String([CertifyPowerShell.RequestInterop]::MakePfx($certificatePem, $csr.PrivateKeyBlobBase64)))
            }
        }
        catch {
            Write-Host "[X] Error requesting the certificate: $($_.Exception.Message)"
            Write-Host ''
            Write-Host "[*] Private Key (PEM)       :"
            Write-Host ''

            if ($effectiveOutputPem) {
                Write-Host -NoNewline $csr.PrivateKeyPem
            }
            else {
                Write-Host ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($csr.PrivateKeyPem)))
            }
        }
    }
    finally {
        if ($didImpersonate) {
            [void][CertifyPowerShell.RequestInterop]::RevertToSelf()
        }
    }
}

Export-ConsoleOutput -Path $OutFile -ScriptBlock {
    Invoke-CertRequest
}
