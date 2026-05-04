[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'ACTIVE DIRECTORY / IDENTITY MISCONFIG CHECKS'
$domain = Get-PrivCheckDomainContext
if (-not $domain) {
  Write-Host 'Host appears to be in a workgroup or AD context could not be resolved.' -ForegroundColor DarkGray
  return
}
$ntlm = Get-PrivCheckNtlmPolicySummary
if ($ntlm) {
  $recv = if ($null -ne $ntlm.RestrictReceiving) { [int]$ntlm.RestrictReceiving } else { -1 }
  $send = if ($null -ne $ntlm.RestrictSending) { [int]$ntlm.RestrictSending } else { -1 }
  $lm = if ($null -ne $ntlm.LmCompatibility) { [int]$ntlm.LmCompatibility } else { -1 }
  Write-Host ("NTLM policy: Receiving:{0} Sending:{1} LMCompat:{2}" -f $recv, $send, $lm)
}
$time = Get-PrivCheckTimeSkewInfo -DomainContext $domain
if ($time) {
  $color = if ([math]::Abs($time.OffsetSeconds) -gt 5) { 'Yellow' } else { 'Gray' }
  Write-Host ("Kerberos time offset vs {0}: {1:N3}s (sample: {2})" -f $time.Source, $time.OffsetSeconds, $time.RawSample.Trim()) -ForegroundColor $color
}
$dns = @(Get-PrivCheckWeakDnsUpdateFinding -DomainContext $domain)
if ($dns.Count) { $dns | Format-Table Zone, Partition, Principal, Rights -AutoSize -Wrap } else { Write-Host 'No obvious insecure dynamic DNS ACLs found with current privileges.' }
$spn = @(Get-PrivCheckPrivilegedSpnTarget -DomainContext $domain)
if ($spn.Count) { $spn | Format-Table User, Groups -AutoSize -Wrap } else { Write-Host 'No privileged SPN users detected via quick LDAP search.' }
$gmsa = @(Get-PrivCheckGmsaReaderReport -DomainContext $domain)
if ($gmsa.Count) { $gmsa | Format-Table Account, WeakPrincipals, Allowed -AutoSize -Wrap } else { Write-Host 'No gMSA objects found via LDAP.' }
$adcs = Get-PrivCheckAdcsSchannelInfo
if ($null -ne $adcs.MappingValue) {
  Write-Host ('Schannel CertificateMappingMethods=0x{0:X}; UPN mapping allowed: {1}; AD CS service: {2}' -f [int]$adcs.MappingValue, $adcs.UpnMapping, $adcs.ServiceState)
}
else { Write-Host 'Could not read Schannel certificate mapping configuration.' -ForegroundColor DarkGray }
