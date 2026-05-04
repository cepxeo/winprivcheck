param(
  [switch]$TimeStamp,
  [switch]$FullCheck,
  [switch]$Excel
)

$script:PrivCheckStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Write-PrivCheckSection {
  param([Parameter(Mandatory)][string]$Title)
  Write-Host ""
  if ($script:TimeStamp -or $TimeStamp) {
    Write-Host ("Time Running: {0}:{1}" -f $script:PrivCheckStopwatch.Elapsed.Minutes, $script:PrivCheckStopwatch.Elapsed.Seconds)
  }
  Write-Host -ForegroundColor Blue ("=========|| {0}" -f $Title)
}

function Convert-PrivCheckSidToName {
  param($SidInput)
  if ($null -eq $SidInput) { return $null }
  try {
    if ($SidInput -is [System.Security.Principal.SecurityIdentifier]) {
      $sidObject = $SidInput
    }
    else {
      $sidObject = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $SidInput
    }
    return $sidObject.Translate([System.Security.Principal.NTAccount]).Value
  }
  catch {
    try { return $sidObject.Value } catch { return [string]$SidInput }
  }
}

function Get-PrivCheckIdentities {
  $identities = @()
  try {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $identities += $currentIdentity.Name
    foreach ($group in $currentIdentity.Groups) {
      $identities += Convert-PrivCheckSidToName $group
    }
  }
  catch {
    $identities += "$env:COMPUTERNAME\$env:USERNAME"
  }
  return (
    $identities |
      Where-Object { $_ -and $_ -ne 'BUILTIN\Administrators' } |
      Sort-Object -Unique
  )
}

function Test-PrivCheckAcl {
  param(
    [Parameter(Mandatory)][string]$Target,
    [string]$ServiceName
  )
  if (-not $Target) { return }

  try {
    $acl = Get-Acl -Path $Target -ErrorAction Stop
  }
  catch {
    try {
      $parent = Split-Path -Path $Target -ErrorAction Stop
      if ($parent -and $parent -ne $Target) { Test-PrivCheckAcl -Target $parent -ServiceName $ServiceName }
    }
    catch { }
    return
  }

  $found = $false
  foreach ($identity in Get-PrivCheckIdentities) {
    if ($acl.Owner -like $identity) {
      Write-Host "$identity owns $Target" -ForegroundColor Red
      $found = $true
    }
    foreach ($permission in ($acl.Access | Where-Object { $_.IdentityReference -like $identity })) {
      $rights = @($permission.FileSystemRights, $permission.RegistryRights) -join ','
      if ($rights -match 'FullControl|Write|Modify') {
        if ($ServiceName) { Write-Host "$ServiceName found with permissions issue:" -ForegroundColor Red }
        Write-Host ("Identity {0} has risky rights ({1}) over {2}" -f $permission.IdentityReference, $rights, $Target) -ForegroundColor Red
        $found = $true
      }
    }
  }

  if (-not $found -and $Target.Length -gt 3) {
    try {
      $parent = Split-Path -Path $Target -ErrorAction Stop
      if ($parent -and $parent -ne $Target) { Test-PrivCheckAcl -Target $parent -ServiceName $ServiceName }
    }
    catch { }
  }
}

function Get-PrivCheckHotFixId {
  param([string]$Title)
  $match = ($Title | Select-String -AllMatches -Pattern 'KB(\d{4,7})').Matches.Value
  if ($match) { return $match }
  return $Title
}

function Get-PrivCheckInstalledApplication {
  param([string[]]$Keys = @('', '\Wow6432Node'))
  foreach ($key in $Keys) {
    try {
      $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $env:COMPUTERNAME).OpenSubKey("SOFTWARE$key\Microsoft\Windows\CurrentVersion\Uninstall")
      if (-not $base) { continue }
      foreach ($app in $base.GetSubKeyNames()) {
        $program = $base.OpenSubKey($app)
        $name = $program.GetValue('DisplayName')
        if ($name) {
          [pscustomobject]@{
            Computername    = $env:COMPUTERNAME
            Software        = $name
            Version         = $program.GetValue('DisplayVersion')
            Publisher       = $program.GetValue('Publisher')
            InstallDate     = $program.GetValue('InstallDate')
            UninstallString = $program.GetValue('UninstallString')
            Architecture    = if ($key -eq '\Wow6432Node') { 'x86' } else { 'x64' }
            Path            = $program.Name
          }
        }
      }
    }
    catch { continue }
  }
}

function Get-PrivCheckRegexSearch {
  param([switch]$FullCheck)
  $regex = [ordered]@{
    'Simple Passwords1' = 'pass.*[=:].+'
    'Simple Passwords2' = 'pwd.*[=:].+'
    'Usernames1' = 'username[=:].+'
    'Usernames2' = 'user[=:].+'
    'Usernames3' = 'login[=:].+'
    'Emails' = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}'
    'Net user add' = 'net user .+ /add'
    'Authorization Basic' = 'basic [a-zA-Z0-9_:\.=\-]+'
    'Authorization Bearer' = 'bearer [a-zA-Z0-9_\.=\-]+'
    'AWS Client ID' = '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'
    'AWS Secret Key' = 'aws(.{0,20})?[''"][0-9a-zA-Z\/+]{40}[''"]'
    'Basic Auth Credentials' = '://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+'
    'Config Secrets' = 'passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|secret:|secretName:'
    'Private Keys' = '-----BEGIN PRIVATE KEY-----|-----BEGIN RSA PRIVATE KEY-----|-----BEGIN OPENSSH PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----|-----BEGIN DSA PRIVATE KEY-----|-----BEGIN EC PRIVATE KEY-----'
    'IPs' = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
  }
  if ($FullCheck) {
    $regex['GitHub Personal Access Token'] = 'ghp_[0-9a-zA-Z]{36}'
    $regex['GitHub Fine-Grained Personal Access Token'] = 'github_pat_[0-9a-zA-Z_]{82}'
    $regex['GitLab Personal Access Token'] = 'glpat-[0-9a-zA-Z\-]{20}'
    $regex['Google API Key'] = 'AIza[0-9A-Za-z_\-]{35}'
    $regex['JWT'] = '(ey[0-9a-z]{30,34}\.ey[0-9a-z\/_\-]{30,}\.[0-9a-zA-Z\/_\-]{10,}={0,2})'
    $regex['OpenAI API Token'] = 'sk-[A-Za-z0-9]{48}'
    $regex['Slack Token'] = 'xox[baprs]-([0-9a-zA-Z]{10,48})?'
    $regex['Slack Webhook'] = 'https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}'
    $regex['Stripe Key'] = '(sk|pk)_(test|live)_[0-9a-z]{10,32}|k_live_[0-9a-zA-Z]{24}'
    $regex['Generic API Key'] = '((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}[''"]([0-9a-zA-Z_=\-]{8,64})[''"]'
  }
  return $regex
}

function Search-PrivCheckExcel {
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$SearchText
  )
  $excelApp = $null
  try {
    $excelApp = New-Object -ComObject Excel.Application
    $workbook = $excelApp.Workbooks.Open((Convert-Path $Source))
    foreach ($worksheet in @($workbook.Sheets)) {
      $found = $worksheet.Cells.Find($SearchText)
      if (-not $found) { continue }
      $first = $found.Address(0, 0, 1, 1)
      do {
        [pscustomobject]@{
          File      = $Source
          WorkSheet = $worksheet.Name
          Column    = $found.Column
          Row       = $found.Row
          TextMatch = $found.Text
          Address   = $found.Address(0, 0, 1, 1)
        }
        $found = $worksheet.Cells.FindNext($found)
      } until (-not $found -or $found.Address(0, 0, 1, 1) -eq $first)
    }
  }
  catch {
    Write-Warning "Unable to search Excel file $Source"
  }
  finally {
    try { if ($workbook) { $workbook.Close($false) } } catch { }
    try { if ($excelApp) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($excelApp) } } catch { }
    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()
  }
}

function Get-PrivCheckDomainContext {
  try { return [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() }
  catch { return $null }
}

function Get-PrivCheckWeakDnsUpdateFinding {
  param([System.DirectoryServices.ActiveDirectory.Domain]$DomainContext)
  if (-not $DomainContext) { return @() }
  $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
  $forestDN = $DomainContext.Forest.RootDomain.GetDirectoryEntry().distinguishedName
  $paths = @(
    "LDAP://CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN",
    "LDAP://CN=MicrosoftDNS,DC=ForestDnsZones,$forestDN",
    "LDAP://CN=MicrosoftDNS,$domainDN"
  )
  $weak = 'authenticated users', 'everyone', 'domain users'
  $danger = 'GenericAll', 'GenericWrite', 'CreateChild', 'WriteProperty', 'WriteDacl', 'WriteOwner'
  $findings = @()
  foreach ($path in $paths) {
    try {
      $container = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $path
      $null = $container.NativeGuid
      $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $container
      $searcher.Filter = '(objectClass=dnsZone)'
      $searcher.PageSize = 500
      foreach ($result in $searcher.FindAll()) {
        try {
          $zone = $result.GetDirectoryEntry()
          $zone.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
          foreach ($ace in $zone.ObjectSecurity.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $principal = Convert-PrivCheckSidToName $ace.IdentityReference
            $rights = $ace.ActiveDirectoryRights.ToString()
            if (($weak | Where-Object { $principal.ToLower() -like "*$_*" }) -and ($danger | Where-Object { $rights -like "*$_*" })) {
              $findings += [pscustomobject]@{
                Zone      = $zone.Properties['name'].Value
                Partition = $path.Split(',')[1]
                Principal = $principal
                Rights    = $rights
              }
            }
          }
        }
        catch { }
      }
    }
    catch { continue }
  }
  return $findings | Sort-Object Zone, Principal -Unique
}

function Get-PrivCheckGmsaReaderReport {
  param([System.DirectoryServices.ActiveDirectory.Domain]$DomainContext)
  if (-not $DomainContext) { return @() }
  try {
    $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
    $root = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$domainDN"
    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $root
    $searcher.Filter = '(&(objectClass=msDS-GroupManagedServiceAccount))'
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.Add('sAMAccountName')
    [void]$searcher.PropertiesToLoad.Add('msDS-GroupMSAMembership')
    $results = $searcher.FindAll()
  }
  catch { return @() }
  foreach ($result in $results) {
    $principals = @()
    foreach ($blob in $result.Properties['msds-groupmsamembership']) {
      try {
        $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$blob, 0)
        foreach ($ace in $raw.DiscretionaryAcl) {
          $name = Convert-PrivCheckSidToName $ace.SecurityIdentifier
          if ($name) { $principals += $name }
        }
      }
      catch { }
    }
    if ($principals.Count -gt 0) {
      $principals = $principals | Sort-Object -Unique
      $weak = $principals | Where-Object { $_ -match 'Domain Users|Authenticated Users|Everyone' }
      [pscustomobject]@{
        Account        = ($result.Properties['samaccountname'] | Select-Object -First 1)
        Allowed        = $principals -join ', '
        WeakPrincipals = if ($weak) { $weak -join ', ' } else { '' }
      }
    }
  }
}

function Get-PrivCheckPrivilegedSpnTarget {
  param([System.DirectoryServices.ActiveDirectory.Domain]$DomainContext)
  if (-not $DomainContext) { return @() }
  $keywords = 'Domain Admin', 'Enterprise Admin', 'Administrators', 'Exchange', 'IT_', 'Schema Admin', 'Account Operator', 'Server Operator', 'Backup Operator', 'DnsAdmin'
  try {
    $domainDN = $DomainContext.GetDirectoryEntry().distinguishedName
    $root = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList "LDAP://$domainDN"
    $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $root
    $searcher.Filter = '(&(objectClass=user)(servicePrincipalName=*))'
    $searcher.PageSize = 500
    [void]$searcher.PropertiesToLoad.Add('sAMAccountName')
    [void]$searcher.PropertiesToLoad.Add('memberOf')
    $results = $searcher.FindAll()
  }
  catch { return @() }
  foreach ($result in $results) {
    $groups = @()
    foreach ($group in $result.Properties['memberof']) {
      $cn = ($group -split ',')[0] -replace '^CN=', ''
      if ($keywords | Where-Object { $cn -like "*$_*" }) { $groups += $cn }
    }
    if ($groups.Count -gt 0) {
      [pscustomobject]@{
        User   = ($result.Properties['samaccountname'] | Select-Object -First 1)
        Groups = ($groups | Sort-Object -Unique) -join ', '
      }
    }
  }
}

function Get-PrivCheckNtlmPolicySummary {
  try { $msv = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction Stop }
  catch { return $null }
  $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
  [pscustomobject]@{
    RestrictReceiving = $msv.RestrictReceivingNTLMTraffic
    RestrictSending   = $msv.RestrictSendingNTLMTraffic
    LmCompatibility   = if ($lsa) { $lsa.LmCompatibilityLevel } else { $null }
  }
}

function Get-PrivCheckTimeSkewInfo {
  param([System.DirectoryServices.ActiveDirectory.Domain]$DomainContext)
  if (-not $DomainContext) { return $null }
  try { $pdc = $DomainContext.PdcRoleOwner.Name } catch { return $null }
  try {
    $sample = (w32tm /stripchart /computer:$pdc /dataonly /samples:3 2>$null | Where-Object { $_ -match ',' } | Select-Object -Last 1)
    if (-not $sample) { return $null }
    $offsetText = $sample.Split(',')[1].Trim().TrimEnd('s')
    [double]$offset = 0
    if (-not [double]::TryParse($offsetText, [ref]$offset)) { return $null }
    [pscustomobject]@{ Source = $pdc; OffsetSeconds = $offset; RawSample = $sample }
  }
  catch { return $null }
}

function Get-PrivCheckAdcsSchannelInfo {
  $info = [ordered]@{ MappingValue = $null; UpnMapping = $false; ServiceState = $null }
  try {
    $schannel = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name CertificateMappingMethods -ErrorAction Stop
    $info.MappingValue = $schannel.CertificateMappingMethods
    $info.UpnMapping = (($schannel.CertificateMappingMethods -band 0x4) -eq 0x4)
  }
  catch { }
  $svc = Get-Service -Name certsrv -ErrorAction SilentlyContinue
  if ($svc) { $info.ServiceState = $svc.Status }
  [pscustomobject]$info
}
