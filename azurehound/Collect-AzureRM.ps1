[CmdletBinding()]
param(
    [string[]] $SubscriptionId,
    [string[]] $ManagementGroupId,
    [string] $OutputPath,
    [switch] $SkipRelationships,
    [switch] $ContinueOnError
)

. "$PSScriptRoot/AzCliAzureHound.Common.ps1"

function Get-ArmCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [Parameter(Mandatory = $true)]
        [string] $ApiVersion,

        [hashtable] $Query = @{},

        [switch] $ContinueOnError
    )

    $queryWithVersion = @{}
    foreach ($key in $Query.Keys) {
        $queryWithVersion[$key] = $Query[$key]
    }
    $queryWithVersion["api-version"] = $ApiVersion

    $uri = "https://management.azure.com$Path$(ConvertTo-QueryString -Query $queryWithVersion)"
    Invoke-AzRestCollection -Uri $uri -ContinueOnError:$ContinueOnError
}

function Add-CollectionRecords {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]] $Records,

        [Parameter(Mandatory = $true)]
        [string] $Kind,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object[]] $Items,

        [string] $SubscriptionId,
        [string] $TenantId
    )

    foreach ($item in $Items) {
        if (-not [string]::IsNullOrWhiteSpace($SubscriptionId)) {
            $item | Add-Member -NotePropertyName "subscriptionId" -NotePropertyValue "/subscriptions/$SubscriptionId" -Force
        }
        if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
            $item | Add-Member -NotePropertyName "tenantId" -NotePropertyValue $TenantId -Force
        }
        $Records.Add((New-AzureHoundRecord -Kind $Kind -Data $item))
    }
}

function Get-ScopeRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ScopeId,

        [switch] $ContinueOnError
    )

    Get-ArmCollection -Path "$ScopeId/providers/Microsoft.Authorization/roleAssignments" `
        -ApiVersion "2015-07-01" `
        -Query @{ '$filter' = "atScope()" } `
        -ContinueOnError:$ContinueOnError
}

function Add-ResourceRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]] $Records,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object[]] $Resources,

        [Parameter(Mandatory = $true)]
        [string] $RecordKind
    )

    foreach ($resource in $Resources) {
        $assignments = Get-ScopeRoleAssignments -ScopeId $resource.id -ContinueOnError:$ContinueOnError
        $items = foreach ($assignment in $assignments) {
            [pscustomobject]@{
                resourceId = $resource.id
                roleAssignment = $assignment
            }
        }
        $records.Add((New-AzureHoundRecord -Kind $RecordKind -Data ([pscustomobject]@{
            resourceId = $resource.id
            roleAssignments = @($items)
        })))
    }
}

Assert-AzCliAvailable

$tenant = Invoke-AzCliJson -CommandName "az account show" -ScriptBlock {
    az account show --only-show-errors
}
$tenantId = $tenant.tenantId

$records = [System.Collections.Generic.List[object]]::new()

$subscriptions = Get-ArmCollection -Path "/subscriptions" -ApiVersion "2020-01-01" -ContinueOnError:$ContinueOnError
if (@($SubscriptionId).Count -gt 0) {
    $subscriptionSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $SubscriptionId) {
        $null = $subscriptionSet.Add($id.Trim("/").Split("/")[-1])
    }
    $subscriptions = @($subscriptions | Where-Object { $subscriptionSet.Contains($_.subscriptionId) })
}

foreach ($subscription in $subscriptions) {
    $subscription | Add-Member -NotePropertyName "tenantId" -NotePropertyValue $tenantId -Force
    $records.Add((New-AzureHoundRecord -Kind "AZSubscription" -Data $subscription))
}

$managementGroups = Get-ArmCollection -Path "/providers/Microsoft.Management/managementGroups" -ApiVersion "2020-05-01" -ContinueOnError:$ContinueOnError
if (@($ManagementGroupId).Count -gt 0) {
    $mgSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $ManagementGroupId) {
        $null = $mgSet.Add($id)
    }
    $managementGroups = @($managementGroups | Where-Object { $mgSet.Contains($_.name) -or $mgSet.Contains($_.id) })
}
Add-CollectionRecords -Records $records -Kind "AZManagementGroup" -Items $managementGroups -TenantId $tenantId

$resourceGroups = [System.Collections.Generic.List[object]]::new()
$keyVaults = [System.Collections.Generic.List[object]]::new()
$virtualMachines = [System.Collections.Generic.List[object]]::new()
$functionApps = [System.Collections.Generic.List[object]]::new()
$webApps = [System.Collections.Generic.List[object]]::new()
$automationAccounts = [System.Collections.Generic.List[object]]::new()
$containerRegistries = [System.Collections.Generic.List[object]]::new()
$logicApps = [System.Collections.Generic.List[object]]::new()
$managedClusters = [System.Collections.Generic.List[object]]::new()
$vmScaleSets = [System.Collections.Generic.List[object]]::new()

foreach ($subscription in $subscriptions) {
    $sid = $subscription.subscriptionId

    $rgs = Get-ArmCollection -Path "/subscriptions/$sid/resourcegroups" -ApiVersion "2021-04-01" -ContinueOnError:$ContinueOnError
    foreach ($item in $rgs) { $resourceGroups.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZResourceGroup" -Items $rgs -SubscriptionId $sid -TenantId $tenantId

    $kvs = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.KeyVault/vaults" -ApiVersion "2019-09-01" -ContinueOnError:$ContinueOnError
    foreach ($item in $kvs) { $keyVaults.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZKeyVault" -Items $kvs -SubscriptionId $sid -TenantId $tenantId

    $vms = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Compute/virtualMachines" -ApiVersion "2021-07-01" -ContinueOnError:$ContinueOnError
    foreach ($item in $vms) { $virtualMachines.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZVM" -Items $vms -SubscriptionId $sid -TenantId $tenantId

    $sites = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Web/sites" -ApiVersion "2022-03-01" -ContinueOnError:$ContinueOnError
    $funcs = @($sites | Where-Object { $_.kind -match "functionapp" })
    $apps = @($sites | Where-Object { $_.kind -notmatch "functionapp" })
    foreach ($item in $funcs) { $functionApps.Add($item) }
    foreach ($item in $apps) { $webApps.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZFunctionApp" -Items $funcs -SubscriptionId $sid -TenantId $tenantId
    Add-CollectionRecords -Records $records -Kind "AZWebApp" -Items $apps -SubscriptionId $sid -TenantId $tenantId

    $automation = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Automation/automationAccounts" -ApiVersion "2021-06-22" -ContinueOnError:$ContinueOnError
    foreach ($item in $automation) { $automationAccounts.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZAutomationAccount" -Items $automation -SubscriptionId $sid -TenantId $tenantId

    $registries = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.ContainerRegistry/registries" -ApiVersion "2023-01-01-preview" -ContinueOnError:$ContinueOnError
    foreach ($item in $registries) { $containerRegistries.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZContainerRegistry" -Items $registries -SubscriptionId $sid -TenantId $tenantId

    $workflows = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Logic/workflows" -ApiVersion "2016-06-01" -ContinueOnError:$ContinueOnError
    foreach ($item in $workflows) { $logicApps.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZLogicApp" -Items $workflows -SubscriptionId $sid -TenantId $tenantId

    $clusters = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.ContainerService/managedClusters" -ApiVersion "2021-07-01" -ContinueOnError:$ContinueOnError
    foreach ($item in $clusters) { $managedClusters.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZManagedCluster" -Items $clusters -SubscriptionId $sid -TenantId $tenantId

    $scaleSets = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Compute/virtualMachineScaleSets" -ApiVersion "2022-11-01" -ContinueOnError:$ContinueOnError
    foreach ($item in $scaleSets) { $vmScaleSets.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZVMScaleSet" -Items $scaleSets -SubscriptionId $sid -TenantId $tenantId
}

if (-not $SkipRelationships) {
    foreach ($group in $managementGroups) {
        $descendants = Get-ArmCollection -Path "/providers/Microsoft.Management/managementGroups/$($group.name)/descendants" -ApiVersion "2020-05-01" -ContinueOnError:$ContinueOnError
        foreach ($descendant in $descendants) {
            $records.Add((New-AzureHoundRecord -Kind "AZManagementGroupDescendant" -Data ([pscustomobject]@{
                managementGroupId = $group.id
                descendant = $descendant
            })))
        }

        $assignments = Get-ScopeRoleAssignments -ScopeId $group.id -ContinueOnError:$ContinueOnError
        Add-AzureHoundRoleAssignmentRecords -Records $records -ScopeKind "ManagementGroup" -RecordKind "AZManagementGroupRoleAssignment" -ContainerPropertyName "managementGroupId" -ScopeId $group.id -Assignments $assignments
    }

    foreach ($subscription in $subscriptions) {
        $scope = "/subscriptions/$($subscription.subscriptionId)"
        $assignments = Get-ScopeRoleAssignments -ScopeId $scope -ContinueOnError:$ContinueOnError
        Add-AzureHoundRoleAssignmentRecords -Records $records -ScopeKind "Subscription" -RecordKind "AZSubscriptionRoleAssignment" -ContainerPropertyName "subscriptionId" -ScopeId $scope -Assignments $assignments
    }

    foreach ($rg in $resourceGroups) {
        $assignments = Get-ScopeRoleAssignments -ScopeId $rg.id -ContinueOnError:$ContinueOnError
        Add-AzureHoundRoleAssignmentRecords -Records $records -ScopeKind "ResourceGroup" -RecordKind "AZResourceGroupRoleAssignment" -ContainerPropertyName "resourceGroupId" -ScopeId $rg.id -Assignments $assignments
    }

    foreach ($kv in $keyVaults) {
        foreach ($policy in $kv.properties.accessPolicies) {
            $permissions = @($policy.permissions.keys) + @($policy.permissions.secrets) + @($policy.permissions.certificates)
            if (@($permissions | Where-Object { $_ -eq "Get" }).Count -gt 0) {
                $policy | Add-Member -NotePropertyName "keyVaultId" -NotePropertyValue $kv.id -Force
                $records.Add((New-AzureHoundRecord -Kind "AZKeyVaultAccessPolicy" -Data $policy))
            }
        }

        $assignments = Get-ScopeRoleAssignments -ScopeId $kv.id -ContinueOnError:$ContinueOnError
        Add-AzureHoundRoleAssignmentRecords -Records $records -ScopeKind "KeyVault" -RecordKind "AZKeyVaultRoleAssignment" -ContainerPropertyName "keyVaultId" -ScopeId $kv.id -Assignments $assignments
    }

    foreach ($vm in $virtualMachines) {
        $assignments = Get-ScopeRoleAssignments -ScopeId $vm.id -ContinueOnError:$ContinueOnError
        Add-AzureHoundRoleAssignmentRecords -Records $records -ScopeKind "VM" -RecordKind "AZVMRoleAssignment" -ContainerPropertyName "vmId" -ScopeId $vm.id -Assignments $assignments
    }

    Add-ResourceRoleAssignments -Records $records -Resources $functionApps -RecordKind "AZFunctionAppRoleAssignment"
    Add-ResourceRoleAssignments -Records $records -Resources $webApps -RecordKind "AZWebAppRoleAssignment"
    Add-ResourceRoleAssignments -Records $records -Resources $automationAccounts -RecordKind "AZAutomationAccountRoleAssignment"
    Add-ResourceRoleAssignments -Records $records -Resources $containerRegistries -RecordKind "AZContainerRegistryRoleAssignment"
    Add-ResourceRoleAssignments -Records $records -Resources $logicApps -RecordKind "AZLogicAppRoleAssignment"
    Add-ResourceRoleAssignments -Records $records -Resources $managedClusters -RecordKind "AZManagedClusterRoleAssignment"
    Add-ResourceRoleAssignments -Records $records -Resources $vmScaleSets -RecordKind "AZVMScaleSetRoleAssignment"
}

Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
