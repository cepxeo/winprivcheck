# Certify Defensive PowerShell Reimplementation

This folder reimplements the Certify command surface as **separate PowerShell scripts** for defensive/internal use.

## Design

- One script per original command/technique.
- Read-only enumeration commands preserve practical audit functionality.
- High-risk technique commands are reimplemented as **simulation + control-check** workflows.
- No offensive execution or PKI mutation is performed.

## Scripts

- `enum-cas.ps1` - Enumerate enterprise CAs from AD.
- `enum-templates.ps1` - Enumerate and score certificate templates for risk indicators.
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

# Enumerate templates and show likely-risky ones
.\enum-templates.ps1 -FilterVulnerable -OutFile .\reports\templates-risk.json

# Run a defensive simulation for request-agent technique
.\request-agent.ps1 -CAName "corp-CA01\corp-CA01-CA" -AgentTemplate "EnrollmentAgent" -TargetTemplate "User" -OnBehalfOf "CORP\alice"

# Use dispatcher
.\Invoke-CertifyDefensive.ps1 -Command "manage-template" -Arguments @{
    Template = "User"
    Action   = "Enable-SAN"
}
```
