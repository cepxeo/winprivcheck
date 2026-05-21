# Azure CLI PowerShell Collection Scripts

These scripts provide a PowerShell implementation of the broad AzureHound collection flow using an existing Azure CLI login. They call `az rest` and `az account` directly, so the machine running them only needs PowerShell and Azure CLI.

## Usage

```powershell
az login
./scripts/Invoke-AzCliAzureHoundCollection.ps1 -OutputPath ./azurehound-azcli.json
```

Collect only Entra ID objects:

```powershell
./scripts/Invoke-AzCliAzureHoundCollection.ps1 -Scope AzureAD -OutputPath ./azure-ad.json
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

Use `-ContinueOnError` when you expect partial permissions. Use `-SkipRelationships` for a faster object-only inventory.
