# Certify PowerShell Reimplementation

This folder contains one PowerShell script per Certify command. The core commands below now aim to replicate the .NET behavior directly:

- `request.ps1`
- `enum-cas.ps1`
- `enum-templates.ps1`
- `enum-pkiobjects.ps1`

The remaining high-risk/mutation-style commands are still defensive simulations or checklists, as noted in the script overview.

## Requirements

Run these scripts from a domain-joined Windows host under a domain user or an appropriately privileged context.

- Enumeration uses `System.DirectoryServices`, LDAP/RootDSE, current Windows credentials, security descriptors, and in some cases remote registry reads.
- `request.ps1` uses Windows `X509Enrollment` and `CertificateAuthority.Request` COM APIs and must run on Windows with the AD CS client components available.
- `enum-cas.ps1` and `enum-templates.ps1` may contact CA hosts, remote registry, and web enrollment endpoints to mirror Certify’s CA checks.

Start in this folder:

```powershell
Set-Location -Path .\powershell
```

## Recent Changes

- `request.ps1` now performs real certificate request generation/submission/retrieval instead of simulation output.
- `enum-cas.ps1` now mirrors Certify `enum-cas`: Root CAs, NTAuth certificates, Enterprise CAs, permissions, vulnerabilities, web checks, enabled templates.
- `enum-templates.ps1` now mirrors Certify `enum-templates`: Enterprise CA context, template ACLs, ESC-style vulnerability classification, and all template filters.
- `enum-pkiobjects.ps1` now mirrors Certify `enum-pkiobjects`: PKI object controllers, CA host ACLs, admin hiding, and group-linked Enterprise OIDs.
- For these rewritten scripts, `-OutFile` redirects console output to a text file. They no longer emit default JSON reports.

## LDAP Targeting

The rewritten enumeration scripts follow the Certify-style options:

- `-Domain <FQDN>`: query `LDAP://<domain>/RootDSE` for the configuration naming context.
- `-LdapServer <host>`: use a specific LDAP server in LDAP paths.
- `-DomainController` and `-Server` are aliases for `-LdapServer`.

If `-Domain` and `-LdapServer` are omitted, the scripts use `LDAP://RootDSE` and the default LDAP binding for the current logon context.

## Environment Variables

`request.ps1` supports environment fallbacks for parity/convenience. Explicit parameters win.

| Variable | Used by |
|----------|---------|
| `CERTIFY_CA_NAME` | `request`, `request-agent`, `request-download`, `request-renew`, `manage-ca`, `forge` |
| `CERTIFY_TEMPLATE` | `request`, `request-renew`, `manage-template` |
| `CERTIFY_SUBJECT` | `request` (`--subject`) |
| `CERTIFY_UPN`, `CERTIFY_SUBJECTALT_UPN` | `request`; comma-separated = multiple `--upn` |
| `CERTIFY_DNS`, `CERTIFY_SUBJECTALT_DNS` | `request`; comma-separated = multiple `--dns` |
| `CERTIFY_EMAIL`, `CERTIFY_SUBJECTALT_EMAIL` | `request`; comma-separated = multiple `--email` |
| `CERTIFY_SID_URL` | `request` (`--sid-url`; SID value only) |
| `CERTIFY_SID_EXTENSION`, `CERTIFY_SID` | `request` (`--sid`) |
| `CERTIFY_APPLICATION_POLICY`, `CERTIFY_APPLICATION_POLICIES` | `request`; comma-separated OIDs |
| `CERTIFY_KEY_SIZE` | `request` when `-KeySize` is omitted |
| `CERTIFY_MACHINE`, `CERTIFY_MACHINE_CONTEXT` | `request`; `true` / `1` / `yes` means machine context |
| `CERTIFY_OUTPUT_PEM`, `CERTIFY_OUTPUT_CSR`, `CERTIFY_INSTALL` | `request` output/install flags |
| `CERTIFY_SAN` | legacy `request` fallback: one DNS SAN when no UPN/DNS/Email values are supplied |
| `CERTIFY_AGENT_TEMPLATE`, `CERTIFY_TARGET_TEMPLATE`, `CERTIFY_ON_BEHALF_OF` | `request-agent` |
| `CERTIFY_REQUEST_ID` | `request-download` |
| `CERTIFY_CERT_THUMBPRINT` | `request-renew` |
| `CERTIFY_MANAGE_ACTION` | `manage-ca`, `manage-template` |
| `CERTIFY_PRINCIPAL` | `manage-self` |
| `CERTIFY_TARGET_IDENTITY` | `forge` |
| `CERTIFY_COMMAND` | `Invoke-CertifyDefensive.ps1` when `-Command` is omitted |

## Scripts Overview

| File | Purpose |
|------|---------|
| `enum-cas.ps1` | Enumerate CAs, Root CAs, NTAuth certificates, CA permissions, web services, vulnerabilities, and enabled templates. |
| `enum-templates.ps1` | Enumerate certificate templates with Enterprise CA context, ACLs, filters, and vulnerability classification. |
| `enum-pkiobjects.ps1` | Enumerate controllers of PKI objects and optionally group-linked Enterprise OIDs. |
| `request.ps1` | Create/submit/download/install certificate requests using Windows AD CS APIs. |
| `request-agent.ps1` | Defensive simulation for enrollment-agent / on-behalf scenario. |
| `request-download.ps1` | Defensive request retrieval checklist. |
| `request-renew.ps1` | Defensive renewal checklist. |
| `forge.ps1` | Defensive simulation: CA key custody / forgery controls. |
| `manage-ca.ps1` | Defensive simulation: CA administrative change checklist. |
| `manage-template.ps1` | Defensive simulation: template change checklist. |
| `manage-self.ps1` | Defensive simulation: principal / self-enrollment checklist. |
| `Invoke-CertifyDefensive.ps1` | Wrapper that dispatches to a script by command name. |
| `Certify.Defensive.Common.psm1` | Shared helpers used by the remaining defensive scripts. |

## `enum-cas.ps1`

Options:

| Option | Description |
|--------|-------------|
| `-CAName`, `-CA` | Restrict to a CA in `SERVER\CA-NAME` format. |
| `-Domain` | Target domain FQDN. |
| `-LdapServer` | Target LDAP server. Aliases: `-DomainController`, `-Server`. |
| `-CurrentUser` | Classify vulnerabilities for current user and groups. |
| `-TargetUser` | Classify vulnerabilities for a target domain user. |
| `-FilterVulnerable` | Show only CAs with identified vulnerabilities. |
| `-HideAdmins` | Exclude admin permissions from permission output. |
| `-ShowAllPermissions` | Print full ACE details. |
| `-SkipWebServiceChecks` | Skip CA web endpoint checks. |
| `-OutFile` | Redirect console output to a file. |

Examples:

```powershell
.\enum-cas.ps1
.\enum-cas.ps1 -Domain corp.example.com
.\enum-cas.ps1 -LdapServer dc01.corp.example.com -SkipWebServiceChecks
.\enum-cas.ps1 -CA "CORP-CA01\Corporate CA" -ShowAllPermissions
.\enum-cas.ps1 -CurrentUser -FilterVulnerable -OutFile .\reports\cas.txt
```

## `enum-templates.ps1`

Options:

| Option | Description |
|--------|-------------|
| `-CAName`, `-CA` | Restrict CA context to `SERVER\CA-NAME`. |
| `-Template`, `-TemplateName` | Restrict to one certificate template name. |
| `-Domain` | Target domain FQDN. |
| `-LdapServer` | Target LDAP server. Aliases: `-DomainController`, `-Server`. |
| `-CurrentUser` | Classify vulnerabilities for current user and groups. |
| `-TargetUser` | Classify vulnerabilities for a target domain user. |
| `-FilterEnabled` | Show templates published by at least one enumerated CA. |
| `-FilterVulnerable` | Show templates with identified vulnerabilities. |
| `-FilterRequestAgent` | Show request-agent / on-behalf-of templates. |
| `-FilterClientAuth` | Show client-auth-capable templates. |
| `-FilterEnrolleeSuppliesSubject` | Show templates where enrollee supplies subject. Alias: `-FilterSupplySubject`. |
| `-FilterManagerApproval` | Show templates requiring manager approval. |
| `-HideAdmins` | Exclude admin permissions from permission output. |
| `-ShowAllPermissions` | Print full ACE details. |
| `-OutFile` | Redirect console output to a file. |

Examples:

```powershell
.\enum-templates.ps1
.\enum-templates.ps1 -Domain corp.example.com -FilterEnabled
.\enum-templates.ps1 -LdapServer dc01.corp.example.com -FilterVulnerable -FilterClientAuth
.\enum-templates.ps1 -CA "CORP-CA01\Corporate CA" -Template "User"
.\enum-templates.ps1 -CurrentUser -FilterVulnerable -HideAdmins -OutFile .\reports\templates.txt
```

## `enum-pkiobjects.ps1`

Options:

| Option | Description |
|--------|-------------|
| `-Domain` | Target domain FQDN. |
| `-LdapServer` | Target LDAP server. Aliases: `-DomainController`, `-Server`. |
| `-ShowLinkedOids` | Print Enterprise OIDs linked to groups. |
| `-ShowAdmins` | Include admin and SYSTEM principals in controller output. |
| `-OutFile` | Redirect console output to a file. |

Examples:

```powershell
.\enum-pkiobjects.ps1
.\enum-pkiobjects.ps1 -Domain corp.example.com
.\enum-pkiobjects.ps1 -LdapServer dc01.corp.example.com -ShowLinkedOids
.\enum-pkiobjects.ps1 -ShowAdmins -OutFile .\reports\pki-objects.txt
```

## `request.ps1`

Options:

| Option | Description |
|--------|-------------|
| `-CAName`, `-CA` | Target CA in `SERVER\CA-NAME` format. Required unless `CERTIFY_CA_NAME` is set. |
| `-Template`, `-TemplateName` | Target certificate template. Required unless `CERTIFY_TEMPLATE` is set. |
| `-Subject`, `-SubjectName` | Subject DN/name. Defaults like Certify when omitted. |
| `-Upn` | UPN subject alternative name. May be repeated. |
| `-Dns` | DNS subject alternative name. May be repeated. |
| `-Email` | Email subject alternative name. May be repeated. |
| `-SidUrl`, `-SubjectAltNameSid` | SID URL SAN value. |
| `-Sid`, `-SidExtension` | SID security extension value. |
| `-ApplicationPolicy`, `-ApplicationPolicies` | Application policy OID. May be repeated. |
| `-KeySize` | Private key size: `512`, `1024`, `2048`, or `4096`. Default: `2048`. |
| `-MachineContext`, `-Machine` | Request in machine context; attempts SYSTEM impersonation like Certify. |
| `-OutputPem` | Output private key + certificate PEM instead of PFX. |
| `-OutputCSR` | Generate CSR and private key only; do not submit. |
| `-Install` | Install the issued certificate response. |
| `-OutFile` | Redirect console output to a file. |

Examples:

```powershell
.\request.ps1 -CA "CORP-CA01\Corporate CA" -Template "User"

.\request.ps1 -CA "CORP-CA01\Corporate CA" -Template "User" `
  -Subject "CN=Jane Doe,OU=IT,DC=corp,DC=example,DC=com" `
  -Upn "jane@corp.example.com" -Dns "web.corp.example.com" -Email "jane@corp.example.com" `
  -KeySize 4096 -OutputPem

.\request.ps1 -CA "CORP-CA01\Corporate CA" -Template "Computer" `
  -MachineContext -OutputCSR

.\request.ps1 -CA "CORP-CA01\Corporate CA" -Template "User" `
  -SidUrl "S-1-5-21-1111111111-2222222222-3333333333-4444" `
  -ApplicationPolicy "1.3.6.1.5.5.7.3.2" `
  -OutFile .\reports\request.txt
```

## Remaining Defensive Scripts

These scripts still intentionally emit simulation/checklist style output.

### `request-agent.ps1`

Required: `-CAName`, `-AgentTemplate`, `-TargetTemplate`. Optional: `-OnBehalfOf`, `-OutFile`.

```powershell
.\request-agent.ps1 -CAName "CORP-CA01\Corporate CA" `
  -AgentTemplate "Enrollment Agent" `
  -TargetTemplate "User" `
  -OnBehalfOf "CORP\alice"
```

### `request-download.ps1`

Required: `-CAName`, `-RequestId`.

```powershell
.\request-download.ps1 -CAName "CORP-CA01\Corporate CA" -RequestId 42
```

### `request-renew.ps1`

Required: `-CAName`, `-Template`. Optional: `-CertificateThumbprint`, `-OutFile`.

```powershell
.\request-renew.ps1 -CAName "CORP-CA01\Corporate CA" -Template "User"
```

### `forge.ps1`

Optional: `-CAName`, `-TargetIdentity`, `-OutFile`.

```powershell
.\forge.ps1 -CAName "CORP-CA01\Corporate CA" -TargetIdentity "CORP\high-value-account"
```

### `manage-ca.ps1`

Required: `-CAName`. Optional: `-Action`, `-OutFile`.

```powershell
.\manage-ca.ps1 -CAName "CORP-CA01\Corporate CA" -Action "Review-AIA-CDP-URLs"
```

### `manage-template.ps1`

Required: `-Template`. Optional: `-Action`, `-OutFile`.

```powershell
.\manage-template.ps1 -Template "User" -Action "ACL-review"
```

### `manage-self.ps1`

Optional: `-Principal`, `-OutFile`.

```powershell
.\manage-self.ps1
.\manage-self.ps1 -Principal "CORP\pkiaudit_svc"
```

## `Invoke-CertifyDefensive.ps1`

`-Command` selects the script (`enum-cas`, `enum-templates`, `enum-pkiobjects`, `request`, and the remaining defensive scripts). Parameters are forwarded via `-Arguments` as a hashtable. You can omit `-Command` when `$env:CERTIFY_COMMAND` is set.

```powershell
.\Invoke-CertifyDefensive.ps1 -Command "enum-cas" -Arguments @{
  Domain = "corp.example.com"
  SkipWebServiceChecks = $true
}

.\Invoke-CertifyDefensive.ps1 -Command "enum-templates" -Arguments @{
  LdapServer = "dc01.corp.example.com"
  FilterVulnerable = $true
}

.\Invoke-CertifyDefensive.ps1 -Command "request" -Arguments @{
  CAName = "CORP-CA01\Corporate CA"
  Template = "User"
  OutputCSR = $true
}
```

Switch parameters in `-Arguments` must use `$true`.
