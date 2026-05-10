# Certify Defensive PowerShell Reimplementation

This folder reimplements the Certify command surface as **separate PowerShell scripts** for defensive/internal use.

## Design

- One script per original command/technique.
- Read-only enumeration commands preserve practical audit functionality.
- High-risk technique commands are reimplemented as **simulation + control-check** workflows.
- No offensive execution or PKI mutation is performed.
- LDAP and RootDSE use **Negotiate** with **null credentials**, so searches run as the **current domain user / process token** (no scripted alternate credentials).

## Domain controller (automatic)

Enumeration scripts (`enum-cas`, `enum-templates`, `enum-pkiobjects`) choose an LDAP server in this order:

1. `-DomainController`, if passed  
2. `CERTIFY_DC`, `CERTIFY_DEFENSIVE_DC`, or `CERTIFY_DOMAIN_CONTROLLER`  
3. **Auto:** the answering DC's DNS name from `LDAP://RootDSE` **`dnsHostName`** (integrated auth — same discovery as querying RootDSE with no hostname)

Equivalent options you can run interactively:

- **RootDSE (no RSAT):** `[System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE',$null,$null,'Negotiate')` → property `dnsHostName` — this is what the module uses internally (`Get-CertifyDefensiveDiscoveredDomainControllerDns`).
- **RSAT Active Directory module:** `Get-ADDomainController -Discover` (or `-Service GlobalCatalog`).

Rough netbios hint only (not LDAP FQDN): `$env:LOGONSERVER.TrimStart('\\')`.

`enum-templates.ps1` saves JSON under the **process current folder** by default as **`templates-risk.json`** (`Join-Path (Get-Location).Path`). Pass `-OutFile` only to choose a different path. Other scripts export JSON only when you pass `-OutFile`.

## Environment variables

Parameters can be omitted when equivalent variables are set (process scope is usual). **Explicit script parameters override** environment values.

| Variable | Used by |
|----------|---------|
| `CERTIFY_DC`, `CERTIFY_DEFENSIVE_DC`, `CERTIFY_DOMAIN_CONTROLLER` | `enum-*` LDAP host **override only** — if unset, RootDSE `dnsHostName` is used. |
| `CERTIFY_CA_NAME` | `request`, `request-agent`, `request-download`, `request-renew`, `manage-ca`, `forge`. |
| `CERTIFY_TEMPLATE` | `request`, `request-renew`, `manage-template`. |
| `CERTIFY_AGENT_TEMPLATE`, `CERTIFY_TARGET_TEMPLATE`, `CERTIFY_ON_BEHALF_OF` | `request-agent`. |
| `CERTIFY_REQUEST_ID` | `request-download`. |
| `CERTIFY_CERT_THUMBPRINT` | `request-renew`. |
| `CERTIFY_SUBJECT`, `CERTIFY_SAN` | `request`. |
| `CERTIFY_MANAGE_ACTION` | `manage-ca`, `manage-template`. |
| `CERTIFY_PRINCIPAL` | `manage-self` (defaults to `[WindowsIdentity]::GetCurrent().Name`). |
| `CERTIFY_TARGET_IDENTITY` | `forge`. |
| `CERTIFY_COMMAND` | `Invoke-CertifyDefensive.ps1` when `-Command` is omitted. |

Example (LDAP host override only when needed):

```powershell
$env:CERTIFY_DC = "dc01.corp.example.com"
.\enum-templates.ps1 -FilterVulnerable   # writes .\templates-risk.json unless -OutFile is set
```

## Scripts

- `enum-cas.ps1` - Enumerate enterprise CAs from AD.
- `enum-templates.ps1` - Enumerate and score certificate templates for risk indicators (writes `.\templates-risk.json` by default).
- `enum-pkiobjects.ps1` - Enumerate core PKI object classes in AD.
- `request.ps1` - Simulate certificate request controls review.
- `request-agent.ps1` - Simulate enrollment-agent/on-behalf risk review.
- `request-download.ps1` - Simulate request retrieval abuse-path checks.
- `request-renew.ps1` - Simulate renewal abuse-path checks.
- `forge.ps1` - Assess controls that prevent certificate forgery scenarios.
- `manage-ca.ps1` - Simulate CA change-control and hardening review.
- `manage-template.ps1` - Simulate template hardening/change review.
- `manage-self.ps1` - Simulate self-permission risk review.
- `Invoke-CertifyDefensive.ps1` - Dispatcher that calls a command script with arguments.
- `Certify.Defensive.Common.psm1` - Shared helper module.

## Usage

```powershell
cd .\powershell

# Enumerate CAs
.\enum-cas.ps1 -OutFile .\reports\cas.json

# Enumerate templates and show likely-risky ones (default JSON: .\templates-risk.json)
.\enum-templates.ps1 -FilterVulnerable

# Run a defensive simulation for request-agent technique
.\request-agent.ps1 -CAName "corp-CA01\corp-CA01-CA" -AgentTemplate "EnrollmentAgent" -TargetTemplate "User" -OnBehalfOf "CORP\alice"

# Use dispatcher
$env:CERTIFY_COMMAND = "manage-template"
.\Invoke-CertifyDefensive.ps1 -Arguments @{ Template = "User"; Action = "Enable-SAN" }
```
