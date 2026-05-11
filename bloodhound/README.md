# PowerShell DCOnly Collector

`powershell/Invoke-SharpHoundDCOnly.ps1` is a self-contained PowerShell implementation of a SharpHound-style `DCOnly` collection path.

It is intended for environments where you want LDAP-only collection without loading the compiled SharpHound .NET assembly. The script uses .NET `System.DirectoryServices` APIs directly and does not require the ActiveDirectory PowerShell module.

## What It Collects

The script maps to the LDAP-facing intent of SharpHound's `DCOnly` collection method:

- Users
- Computers
- Groups and group membership
- Domain objects
- OUs
- GPOs
- Containers
- Trusted domain objects
- Object properties
- ACL data, unless `-NoACL` is used
- Configuration naming context objects
- ADCS-related objects where present
- GPO local group policy file hints when SYSVOL paths are reachable

The script does not perform computer-side collection such as sessions, logged-on users, local admins, registry collection, SMB checks, or service probing.

## Requirements

- Windows PowerShell on a domain-joined Windows host, or a host that can reach LDAP/LDAPS.
- Network access to a domain controller.
- LDAP permissions for the target directory data.
- Additional privileges may be required to read some security descriptors or sensitive attributes.

No SharpHound binary, SharpHound DLL, or ActiveDirectory module is required.

## Basic Usage

Run against the current domain and write JSON files to the current directory:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1
```

Write output to a specific directory:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -OutputDirectory .\output
```

Create a zip archive after collection:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -OutputDirectory .\output -Zip
```

Use pretty-printed JSON:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -OutputDirectory .\output -PrettyPrint
```

## Domain Targeting

Specify a domain controller:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -DomainController dc01.corp.example.com
```

Specify a domain and domain controller:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -Domain corp.example.com -DomainController dc01.corp.example.com
```

Start collection from a specific distinguished name:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -DistinguishedName "DC=corp,DC=example,DC=com"
```

Search all domains listed in the forest partitions container:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -SearchForest
```

## Authentication And LDAP Options

Use explicit LDAP credentials:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -LdapUsername "CORP\collector" -LdapPassword "Password123!"
```

Use LDAPS:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -DomainController dc01.corp.example.com -SecureLDAP
```

Use a custom LDAP or LDAPS port:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -DomainController dc01.corp.example.com -SecureLDAP -LdapPort 636
```

## Filtering

Append an LDAP filter to the generated collection filter:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -LdapFilter "(adminCount=1)"
```

Collect all LDAP properties requested by the directory service:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -CollectAllProperties
```

Skip ACL/security descriptor collection:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -NoACL
```

## Output

The script writes BloodHound-style JSON wrapper files with `data` and `meta` sections. Output files include:

- `users.json`
- `computers.json`
- `groups.json`
- `domains.json`
- `ous.json`
- `gpos.json`
- `containers.json`
- `trusts.json`
- `certservices.json`
- `acls.json`, unless `-NoACL` is used

Use `-OutputPrefix` to prefix generated file names:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -OutputPrefix corp_dc_only
```

Use a custom zip file path:

```powershell
.\powershell\Invoke-SharpHoundDCOnly.ps1 -Zip -ZipFilename .\output\corp_dc_only.zip
```

## Notes

This script is intentionally LDAP-only. It is useful for low-touch directory collection, quick auditing, and environments where running the compiled ingestor is not desired.

The output structure is SharpHound-inspired, but this script does not use SharpHoundCommon processors. Some advanced BloodHound relationships that require SharpHound's full processing pipeline may not be present or may be represented in a simpler form.
