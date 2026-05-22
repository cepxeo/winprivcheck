# Azure CLI PowerShell Collection Scripts

These scripts provide a PowerShell implementation of the broad AzureHound collection flow using an existing Azure CLI login. They call `az rest` and `az account` directly, so the machine running them only needs PowerShell and Azure CLI.

## Usage

```powershell
az login
./scripts/Invoke-AzCliAzureHoundCollection.ps1 -OutputPath ./azurehound-azcli.json
```

Collect only Entra ID objects:

```powershell
./scripts/Invoke-AzCliAzureHoundCollection.ps1 -Scope AzureAD -ObjectOnly -OutputPath ./azure-ad.json
```

Collect only Azure Resource Manager objects for selected subscriptions:

```powershell
./scripts/Invoke-AzCliAzureHoundCollection.ps1 `
  -Scope AzureRM `
  -SubscriptionId "00000000-0000-0000-0000-000000000000" `
  -OutputPath ./azure-rm.json
```

## Scripts

- `AzCliAzureHound.Common.ps1`: shared Azure CLI invocation, paging, role filtering, and output helpers.
- `Collect-AzureAD.ps1`: users, apps, app owners, federated identity credentials, devices, groups, group owners/members, service principals, service principal owners, app role assignments, tenants, directory roles, directory role assignments, eligibility schedules, and role management policy assignments.
- `Collect-AzureRM.ps1`: management groups, subscriptions, resource groups, key vaults, VMs, function apps, web apps, automation accounts, container registries, logic apps, managed clusters, VM scale sets, descendants, role assignments, selected built-in role relationships, and key vault access policies.
- `Invoke-AzCliAzureHoundCollection.ps1`: combines the AD and RM scripts and writes one AzureHound-style JSON document.

## Notes

The output envelope matches AzureHound's file shape:

```json
{
  "data": [],
  "meta": {
    "type": "azure",
    "version": 5,
    "count": 0
  }
}
```

When `-OutputPath` is set, AzureAD collection also writes per-category files
as each step finishes, for example `azure-ad.users.json`,
`azure-ad.applications.json`, and `azure-ad.role-management-policy-assignments.json`.
These partial files preserve completed data if a later endpoint is denied.

Use `-ContinueOnError` when you expect partial permissions. Use `-SkipRelationships` or `-ObjectOnly` for a faster object-only inventory that avoids relationship, role assignment, and PIM policy endpoints.
Use `-MaxPages` or `-MaxItems` to cap each paged request while testing or when a tenant is very large.
Long-running relationship stages checkpoint partial files every 25 source
objects by default. Use `-ProgressSaveInterval 1` to save after every
application, group, or service principal when you want minimum data loss during
interruptions.

The scripts print timestamped status lines for CLI checks, collection phases,
REST pages, record counts, temporary files, and output writes.

If Microsoft Graph returns a Continuous Access Evaluation challenge such as
`InteractionRequired` or `TokenCreatedWithOutdatedPolicies`, collection pauses
instead of skipping the request. Refresh Azure CLI authentication in another
terminal with `az logout` and `az login`, then press Enter in the collector
window to retry the failed request.

If an `az rest` call fails with exit code 1, rerun with `-ContinueOnError`
to collect everything your current token can read while warning on denied
Graph or Azure Resource Manager endpoints.
