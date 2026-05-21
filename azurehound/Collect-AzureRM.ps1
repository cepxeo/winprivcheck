[CmdletBinding()]
param(
    [string[]] $SubscriptionId,
    [string[]] $ManagementGroupId,
    [string] $OutputPath,
    [int] $MaxPages,
    [int] $MaxItems,
    [switch] $SkipRelationships,
    [switch] $SkipAzCliCheck,
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

        [int] $MaxPages,
        [int] $MaxItems,
        [switch] $ContinueOnError
    )

    $queryWithVersion = @{}
    foreach ($key in $Query.Keys) {
        $queryWithVersion[$key] = $Query[$key]
    }
    $queryWithVersion["api-version"] = $ApiVersion

    $uri = "https://management.azure.com$Path$(ConvertTo-QueryString -Query $queryWithVersion)"
    Invoke-AzRestCollection -Uri $uri -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
}

function Add-CollectionRecords {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Records,

        [Parameter(Mandatory = $true)]
        [string] $Kind,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
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
        -MaxPages $MaxPages `
        -MaxItems $MaxItems `
        -ContinueOnError:$ContinueOnError
}

function Add-ResourceRoleAssignments {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Records,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Resources,

        [Parameter(Mandatory = $true)]
        [string] $RecordKind
    )

    foreach ($resource in $Resources) {
        Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting role assignments for $RecordKind resource $($resource.id)"
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

if (-not $SkipAzCliCheck) {
    Assert-AzCliAvailable
}

Write-AzureHoundStatus -Stage "AZRM" -Message "Reading active tenant from Azure CLI"
$tenant = Invoke-AzCliJson -CommandName "az account show" -Arguments @("account", "show", "--only-show-errors")
$tenantId = $tenant.tenantId
Write-AzureHoundStatus -Stage "AZRM" -Message "Active tenant is $tenantId"

$records = [System.Collections.Generic.List[object]]::new()

Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting subscriptions"
$subscriptions = Get-ArmCollection -Path "/subscriptions" -ApiVersion "2020-01-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
if (@($SubscriptionId).Count -gt 0) {
    Write-AzureHoundStatus -Stage "AZRM" -Message "Filtering to requested subscription id(s): $($SubscriptionId -join ', ')"
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
Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($subscriptions).Count) subscription(s)"

Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting management groups"
$managementGroups = Get-ArmCollection -Path "/providers/Microsoft.Management/managementGroups" -ApiVersion "2020-05-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
if (@($ManagementGroupId).Count -gt 0) {
    Write-AzureHoundStatus -Stage "AZRM" -Message "Filtering to requested management group id(s): $($ManagementGroupId -join ', ')"
    $mgSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $ManagementGroupId) {
        $null = $mgSet.Add($id)
    }
    $managementGroups = @($managementGroups | Where-Object { $mgSet.Contains($_.name) -or $mgSet.Contains($_.id) })
}
Add-CollectionRecords -Records $records -Kind "AZManagementGroup" -Items $managementGroups -TenantId $tenantId
Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($managementGroups).Count) management group(s)"

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
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting resources for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting resource groups for subscription $sid"
    $rgs = Get-ArmCollection -Path "/subscriptions/$sid/resourcegroups" -ApiVersion "2021-04-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $rgs) { $resourceGroups.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZResourceGroup" -Items $rgs -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($rgs).Count) resource group(s) for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting key vaults for subscription $sid"
    $kvs = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.KeyVault/vaults" -ApiVersion "2019-09-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $kvs) { $keyVaults.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZKeyVault" -Items $kvs -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($kvs).Count) key vault(s) for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting virtual machines for subscription $sid"
    $vms = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Compute/virtualMachines" -ApiVersion "2021-07-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $vms) { $virtualMachines.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZVM" -Items $vms -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($vms).Count) virtual machine(s) for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting web and function apps for subscription $sid"
    $sites = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Web/sites" -ApiVersion "2022-03-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    $funcs = @($sites | Where-Object { $_.kind -match "functionapp" })
    $apps = @($sites | Where-Object { $_.kind -notmatch "functionapp" })
    foreach ($item in $funcs) { $functionApps.Add($item) }
    foreach ($item in $apps) { $webApps.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZFunctionApp" -Items $funcs -SubscriptionId $sid -TenantId $tenantId
    Add-CollectionRecords -Records $records -Kind "AZWebApp" -Items $apps -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($funcs).Count) function app(s) and $(@($apps).Count) web app(s) for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting automation accounts for subscription $sid"
    $automation = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Automation/automationAccounts" -ApiVersion "2021-06-22" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $automation) { $automationAccounts.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZAutomationAccount" -Items $automation -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($automation).Count) automation account(s) for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting container registries for subscription $sid"
    $registries = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.ContainerRegistry/registries" -ApiVersion "2023-01-01-preview" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $registries) { $containerRegistries.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZContainerRegistry" -Items $registries -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($registries).Count) container registries for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting logic apps for subscription $sid"
    $workflows = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Logic/workflows" -ApiVersion "2016-06-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $workflows) { $logicApps.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZLogicApp" -Items $workflows -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($workflows).Count) logic app(s) for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting managed clusters for subscription $sid"
    $clusters = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.ContainerService/managedClusters" -ApiVersion "2021-07-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $clusters) { $managedClusters.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZManagedCluster" -Items $clusters -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($clusters).Count) managed cluster(s) for subscription $sid"

    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting virtual machine scale sets for subscription $sid"
    $scaleSets = Get-ArmCollection -Path "/subscriptions/$sid/providers/Microsoft.Compute/virtualMachineScaleSets" -ApiVersion "2022-11-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    foreach ($item in $scaleSets) { $vmScaleSets.Add($item) }
    Add-CollectionRecords -Records $records -Kind "AZVMScaleSet" -Items $scaleSets -SubscriptionId $sid -TenantId $tenantId
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collected $(@($scaleSets).Count) virtual machine scale set(s) for subscription $sid"
}

if (-not $SkipRelationships) {
    Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting Azure RM relationships and role assignments"
    foreach ($group in $managementGroups) {
        Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting descendants and role assignments for management group $($group.name)"
        $descendants = Get-ArmCollection -Path "/providers/Microsoft.Management/managementGroups/$($group.name)/descendants" -ApiVersion "2020-05-01" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
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
        Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting role assignments for subscription $scope"
        $assignments = Get-ScopeRoleAssignments -ScopeId $scope -ContinueOnError:$ContinueOnError
        Add-AzureHoundRoleAssignmentRecords -Records $records -ScopeKind "Subscription" -RecordKind "AZSubscriptionRoleAssignment" -ContainerPropertyName "subscriptionId" -ScopeId $scope -Assignments $assignments
    }

    foreach ($rg in $resourceGroups) {
        Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting role assignments for resource group $($rg.id)"
        $assignments = Get-ScopeRoleAssignments -ScopeId $rg.id -ContinueOnError:$ContinueOnError
        Add-AzureHoundRoleAssignmentRecords -Records $records -ScopeKind "ResourceGroup" -RecordKind "AZResourceGroupRoleAssignment" -ContainerPropertyName "resourceGroupId" -ScopeId $rg.id -Assignments $assignments
    }

    foreach ($kv in $keyVaults) {
        Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting access policies and role assignments for key vault $($kv.id)"
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
        Write-AzureHoundStatus -Stage "AZRM" -Message "Collecting role assignments for virtual machine $($vm.id)"
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
else {
    Write-AzureHoundStatus -Stage "AZRM" -Message "Skipping Azure RM relationship collection"
}

Write-AzureHoundStatus -Stage "AZRM" -Message "Finished Azure RM collection with $($records.Count) record(s)"
Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
