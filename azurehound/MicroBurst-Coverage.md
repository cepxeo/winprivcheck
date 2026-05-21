# MicroBurst-Inspired Azure CLI Checks

This folder now includes `Collect-MicroBurstChecks.ps1`, a dependency-light collector that uses the existing Azure CLI session plus PowerShell only. It is intentionally read-only by default and does not create runbooks, deployment scripts, ACR tasks, VM commands, Kudu commands, or app-service command sessions.

## What MicroBurst Covers

MicroBurst includes several classes of Azure attack-surface and secret-recovery functionality:

- Subscription/resource inventory and domain information.
- Key Vault key, secret, and certificate access checks and extraction.
- App Service and Function App configuration/publishing profile checks, plus Kudu command execution in active extraction modules.
- Automation Account credentials, connections, certificates, runbooks, hybrid workers, custom modules, and Run As/managed identity paths.
- Storage account key listing and public blob/container discovery.
- Azure Container Registry admin credential and repository enumeration, plus managed identity token generation through ACR tasks.
- Managed identity abuse surfaces such as deployment scripts, load testing, VM/Arc run command, and hybrid workers.
- Service-specific secret surfaces including Cosmos DB, AKS kubeconfigs, Service Bus, API Management, App Configuration, Batch, Cognitive Services/OpenAI, Machine Learning, and Load Testing.

## What The New Collector Adds

`Collect-MicroBurstChecks.ps1` adds non-invasive checks for the same broad surfaces:

- Key Vault configuration and whether the current token can list secrets, keys, or certificates.
- Automation Account identities, connections, credentials, certificates, variables, runbooks, custom modules/packages, runtime environments, and hybrid worker groups.
- App Service and Function App identity, Easy Auth configuration, and secret-looking app setting names with values redacted by default.
- Storage account public/shared-key posture, TLS posture, and optional key listing.
- ACR admin-user posture, identity, network posture, and optional credential listing.
- Managed identity surfaces across user-assigned identities, VMs, AKS, Load Testing, Machine Learning, and Container Apps.
- Additional MicroBurst-style secret surfaces such as Cosmos DB, Service Bus, API Management, App Configuration, Batch, Cognitive Services, Machine Learning, and Load Testing.
- With `-IncludeSecretValues`, direct extraction APIs for Key Vault secrets/certificate backing secrets, app settings, publishing profiles, Function keys, Storage keys, ACR credentials, AKS kubeconfigs, Container App secrets, Cosmos DB keys/connection strings, Service Bus namespace/queue/topic keys, API Management subscription/named-value secrets, App Configuration access keys/key-values, Batch keys plus pool/job/task data, Cognitive Services keys, and Machine Learning connection secrets.

Each category is written immediately to a separate JSON file derived from `-OutputPath`, scoped by subscription ID, while the combined output is written at the end.

## Usage

```powershell
.\Collect-MicroBurstChecks.ps1 -OutputPath .\microburst-checks.json
```

Limit scope while testing:

```powershell
.\Collect-MicroBurstChecks.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 -MaxPages 2 -OutputPath .\microburst-checks.json
```

By default, secret-looking configuration values are redacted in output and explicit key/credential/profile listing actions are skipped. To include retrievable secret values and keys from direct Azure APIs:

```powershell
.\Collect-MicroBurstChecks.ps1 -IncludeSecretValues -OutputPath .\microburst-checks.json
```

This collector still avoids MicroBurst techniques that require creating or running code inside Azure resources, such as Automation runbooks, ACR tasks, deployment scripts, Kudu command execution, VM/Arc run command, Bastion shareable link creation, API connection hijacking, and local WireServer VM-extension decryption. The new script covers the read/list/action extraction paths that can run from the current Azure CLI session without dropping payloads into target resources.
