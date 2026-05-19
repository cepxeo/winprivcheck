#requires -version 3

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $ComputerName,

    [string] $DomainController,

    [string] $SearchBase,

    [pscredential] $Credential,

    [switch] $LegacyOnly
)

function Convert-LapsFileTime {
    param([object] $Value)

    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string] $Value)) {
        return $null
    }

    try {
        $FileTime = [int64] $Value
        if ($FileTime -le 0) {
            return $null
        }

        return [datetime]::FromFileTimeUtc($FileTime).ToLocalTime()
    }
    catch {
        return $null
    }
}

function ConvertTo-LdapEscapedValue {
    param([Parameter(Mandatory = $true)][string] $Value)

    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace("`0", '\00')
}

function Get-LegacyLapsPassword {
    $Name = $ComputerName.TrimEnd('$')
    $EscapedName = ConvertTo-LdapEscapedValue -Value $Name
    $EscapedSam = ConvertTo-LdapEscapedValue -Value "$Name`$"
    $Filter = "(&(objectCategory=computer)(|(cn=$EscapedName)(dNSHostName=$EscapedName)(sAMAccountName=$EscapedSam)))"

    if (Get-Command -Name Get-ADComputer -ErrorAction SilentlyContinue) {
        $Params = @{
            LDAPFilter  = $Filter
            Properties  = @('ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'dNSHostName')
            ErrorAction = 'Stop'
        }

        if ($DomainController) { $Params.Server = $DomainController }
        if ($SearchBase) { $Params.SearchBase = $SearchBase }
        if ($Credential) { $Params.Credential = $Credential }

        $Computer = Get-ADComputer @Params | Select-Object -First 1
        if (-not $Computer) {
            throw "Computer '$ComputerName' was not found in Active Directory."
        }

        return [pscustomobject] @{
            ComputerName = if ($Computer.DNSHostName) { $Computer.DNSHostName } else { $Computer.Name }
            Password     = $Computer.'ms-Mcs-AdmPwd'
            Expiration   = Convert-LapsFileTime -Value $Computer.'ms-Mcs-AdmPwdExpirationTime'
            Source       = 'Legacy LAPS'
        }
    }

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
        $DirectoryEntry = New-Object DirectoryServices.DirectoryEntry -ArgumentList @(
            $Root,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    }
    else {
        $DirectoryEntry = New-Object DirectoryServices.DirectoryEntry -ArgumentList $Root
    }

    $Searcher = New-Object DirectoryServices.DirectorySearcher -ArgumentList $DirectoryEntry
    $Searcher.Filter = $Filter
    $Searcher.PageSize = 200
    $null = $Searcher.PropertiesToLoad.Add('dnshostname')
    $null = $Searcher.PropertiesToLoad.Add('name')
    $null = $Searcher.PropertiesToLoad.Add('ms-mcs-admpwd')
    $null = $Searcher.PropertiesToLoad.Add('ms-mcs-admpwdexpirationtime')

    $Result = $Searcher.FindOne()
    if (-not $Result) {
        throw "Computer '$ComputerName' was not found in Active Directory."
    }

    $Props = $Result.Properties
    $HostName = if ($Props.dnshostname.Count) { $Props.dnshostname[0] } else { $Props.name[0] }

    [pscustomobject] @{
        ComputerName = $HostName
        Password     = if ($Props.'ms-mcs-admpwd'.Count) { $Props.'ms-mcs-admpwd'[0] } else { $null }
        Expiration   = if ($Props.'ms-mcs-admpwdexpirationtime'.Count) { Convert-LapsFileTime -Value $Props.'ms-mcs-admpwdexpirationtime'[0] } else { $null }
        Source       = 'Legacy LAPS'
    }
}

try {
    if (-not $LegacyOnly -and (Get-Command -Name Get-LapsADPassword -ErrorAction SilentlyContinue)) {
        $Params = @{
            Identity    = $ComputerName.TrimEnd('$')
            AsPlainText = $true
            ErrorAction = 'Stop'
        }

        if ($DomainController) { $Params.DomainController = $DomainController }
        if ($Credential) { $Params.Credential = $Credential }

        $LapsPassword = Get-LapsADPassword @Params
        [pscustomobject] @{
            ComputerName = $LapsPassword.ComputerName
            Account      = $LapsPassword.Account
            Password     = $LapsPassword.Password
            Expiration   = $LapsPassword.ExpirationTimestamp
            Source       = 'Windows LAPS'
        }

        return
    }

    Get-LegacyLapsPassword
}
catch {
    Write-Error $_
    exit 1
}
