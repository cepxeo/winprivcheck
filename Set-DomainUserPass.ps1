#requires -version 3
<#
.SYNOPSIS
    Resets a domain user's password.

.EXAMPLE
    .\Set-DomainUserPassword.ps1 -Identity jsmith

.EXAMPLE
    $Cred = Get-Credential
    .\Set-DomainUserPassword.ps1 -Identity jsmith -Credential $Cred -DomainController dc01.contoso.local

.EXAMPLE
    $NewPassword = Read-Host "New password" -AsSecureString
    .\Set-DomainUserPassword.ps1 -Identity jsmith -NewPassword $NewPassword

.NOTES
    The account running this script, or the account supplied with -Credential,
    must have permission to reset the target user's password.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Identity,

    [securestring] $NewPassword,

    [string] $DomainController,

    [string] $SearchBase,

    [pscredential] $Credential
)

function ConvertTo-LdapEscapedValue {
    param([Parameter(Mandatory = $true)][string] $Value)

    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace("`0", '\00')
}

function ConvertFrom-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][securestring] $SecureString)

    $Pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pointer)
    }
    finally {
        if ($Pointer -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Pointer)
        }
    }
}

function Find-UserDirectoryEntry {
    $EscapedIdentity = ConvertTo-LdapEscapedValue -Value $Identity
    $Filter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$EscapedIdentity)(userPrincipalName=$EscapedIdentity)(distinguishedName=$EscapedIdentity)))"

    Add-Type -AssemblyName System.DirectoryServices -ErrorAction SilentlyContinue

    if ($DomainController) {
        $Root = "LDAP://$DomainController"
        if ($SearchBase) { $Root = "$Root/$SearchBase" }
    }
    elseif ($SearchBase) {
        $Root = "LDAP://$SearchBase"
    }
    else {
        $RootDse = [adsi] 'LDAP://RootDSE'
        $Root = "LDAP://$($RootDse.defaultNamingContext)"
    }

    if ($Credential) {
        $RootEntry = New-Object DirectoryServices.DirectoryEntry -ArgumentList @(
            $Root,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    }
    else {
        $RootEntry = New-Object DirectoryServices.DirectoryEntry -ArgumentList $Root
    }

    $Searcher = New-Object DirectoryServices.DirectorySearcher -ArgumentList $RootEntry
    $Searcher.Filter = $Filter
    $Searcher.PageSize = 200
    $null = $Searcher.PropertiesToLoad.Add('distinguishedname')
    $null = $Searcher.PropertiesToLoad.Add('samaccountname')

    $Result = $Searcher.FindOne()
    if (-not $Result) {
        throw "User '$Identity' was not found in Active Directory."
    }

    $UserPath = $Result.Path
    if ($Credential) {
        New-Object DirectoryServices.DirectoryEntry -ArgumentList @(
            $UserPath,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    }
    else {
        New-Object DirectoryServices.DirectoryEntry -ArgumentList $UserPath
    }
}

try {
    if (-not $NewPassword) {
        $NewPassword = Read-Host "Enter new password for $Identity" -AsSecureString
    }

    if (Get-Command -Name Set-ADAccountPassword -ErrorAction SilentlyContinue) {
        $AdIdentity = $Identity
        if ($SearchBase -and (Get-Command -Name Get-ADUser -ErrorAction SilentlyContinue)) {
            $EscapedIdentity = ConvertTo-LdapEscapedValue -Value $Identity
            $Filter = "(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=$EscapedIdentity)(userPrincipalName=$EscapedIdentity)(distinguishedName=$EscapedIdentity)))"
            $UserParams = @{
                LDAPFilter  = $Filter
                SearchBase  = $SearchBase
                ErrorAction = 'Stop'
            }

            if ($DomainController) { $UserParams.Server = $DomainController }
            if ($Credential) { $UserParams.Credential = $Credential }

            $AdUser = Get-ADUser @UserParams | Select-Object -First 1
            if (-not $AdUser) {
                throw "User '$Identity' was not found in Active Directory."
            }

            $AdIdentity = $AdUser.DistinguishedName
        }

        $Params = @{
            Identity    = $AdIdentity
            Reset       = $true
            NewPassword = $NewPassword
            ErrorAction = 'Stop'
        }

        if ($DomainController) { $Params.Server = $DomainController }
        if ($Credential) { $Params.Credential = $Credential }

        if ($PSCmdlet.ShouldProcess($Identity, 'Reset domain password')) {
            Set-ADAccountPassword @Params
            Write-Host "Password reset succeeded for '$Identity'."
        }

        return
    }

    $PlainPassword = ConvertFrom-SecureStringToPlainText -SecureString $NewPassword
    $UserEntry = Find-UserDirectoryEntry

    if ($PSCmdlet.ShouldProcess($UserEntry.distinguishedName, 'Reset domain password')) {
        $UserEntry.Invoke('SetPassword', $PlainPassword)
        $UserEntry.CommitChanges()
        Write-Host "Password reset succeeded for '$Identity'."
    }
}
catch {
    Write-Error $_
    exit 1
}
finally {
    if ($PlainPassword) {
        Remove-Variable -Name PlainPassword -Force -ErrorAction SilentlyContinue
    }
}
