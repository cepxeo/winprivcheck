[CmdletBinding()]
param(
    [string] $OutputPath,
    [string] $PartOutputPath,
    [int] $MaxPages,
    [int] $MaxItems,
    [ValidateRange(1, 100000)]
    [int] $ProgressSaveInterval = 25,
    [switch] $SkipRelationships,
    [switch] $SkipAzCliCheck,
    [switch] $ContinueOnError
)

. "$PSScriptRoot/AzCliAzureHound.Common.ps1"

$SplitOutputPath = if ([string]::IsNullOrWhiteSpace($PartOutputPath)) { $OutputPath } else { $PartOutputPath }

function Get-GraphCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [hashtable] $Query = @{},

        [switch] $UseBeta,
        [int] $MaxPages,
        [int] $MaxItems,
        [switch] $ContinueOnError
    )

    $version = if ($UseBeta) { "beta" } else { "v1.0" }
    $uri = "https://graph.microsoft.com/$version/$Path$(ConvertTo-QueryString -Query $Query)"
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
        [object[]] $Items
    )

    foreach ($item in $Items) {
        $Records.Add((New-AzureHoundRecord -Kind $Kind -Data $item))
    }
}

function Add-AndSaveCollectionRecords {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Records,

        [Parameter(Mandatory = $true)]
        [string] $Kind,

        [Parameter(Mandatory = $true)]
        [string] $Suffix,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Items
    )

    $stepRecords = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Items) {
        $record = New-AzureHoundRecord -Kind $Kind -Data $item
        $Records.Add($record)
        $stepRecords.Add($record)
    }

    Write-AzureHoundPartOutput -Records $stepRecords -OutputPath $SplitOutputPath -Suffix $Suffix
}

function Invoke-GraphCollectionStep {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $Kind,

        [Parameter(Mandatory = $true)]
        [string] $Suffix,

        [Parameter(Mandatory = $true)]
        [string] $Path,

        [hashtable] $Query = @{},
        [switch] $UseBeta
    )

    Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting $Label"
    try {
        $items = Get-GraphCollection -Path $Path -Query $Query -UseBeta:$UseBeta -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
    }
    catch {
        Write-Warning ("Skipping {0}: {1}" -f $Label, $_.Exception.Message)
        $items = @()
    }

    Add-AndSaveCollectionRecords -Records $records -Kind $Kind -Suffix $Suffix -Items $items
    Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($items).Count) $Label"
    return @($items)
}

function Get-GraphCollectionOrEmpty {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Label,

        [Parameter(Mandatory = $true)]
        [string] $Path,

        [hashtable] $Query = @{},
        [switch] $UseBeta
    )

    try {
        return @(Get-GraphCollection -Path $Path -Query $Query -UseBeta:$UseBeta -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError)
    }
    catch {
        Write-Warning ("Skipping {0}: {1}" -f $Label, $_.Exception.Message)
        return @()
    }
}

function Add-StepRecord {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $AllRecords,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $StepRecords,

        [Parameter(Mandatory = $true)]
        [string] $Kind,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object] $Data
    )

    $record = New-AzureHoundRecord -Kind $Kind -Data $Data
    $AllRecords.Add($record)
    $StepRecords.Add($record)
}

function Save-StepProgress {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]] $Records,

        [Parameter(Mandatory = $true)]
        [string] $Suffix,

        [Parameter(Mandatory = $true)]
        [int] $CurrentIndex,

        [Parameter(Mandatory = $true)]
        [int] $TotalCount,

        [switch] $Force
    )

    if (-not $Force -and ($CurrentIndex % $ProgressSaveInterval) -ne 0) {
        return
    }

    Write-AzureHoundStatus -Stage "SAVE" -Message "Checkpointing $Suffix after $CurrentIndex/$TotalCount item(s)"
    Write-AzureHoundPartOutput -Records $Records -OutputPath $SplitOutputPath -Suffix $Suffix
}

if (-not $SkipAzCliCheck) {
    Assert-AzCliAvailable
}

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting Entra ID objects"
$records = [System.Collections.Generic.List[object]]::new()

$users = Invoke-GraphCollectionStep -Label "user(s)" -Kind "AZUser" -Suffix "users" -Path "users" -Query @{ '$top' = 999 }
$applications = Invoke-GraphCollectionStep -Label "application(s)" -Kind "AZApp" -Suffix "applications" -Path "applications" -Query @{ '$top' = 99 }
$devices = Invoke-GraphCollectionStep -Label "device(s)" -Kind "AZDevice" -Suffix "devices" -Path "devices" -Query @{ '$top' = 999 }
$groups = Invoke-GraphCollectionStep -Label "group(s)" -Kind "AZGroup" -Suffix "groups" -Path "groups" -Query @{ '$top' = 999 }
$servicePrincipals = Invoke-GraphCollectionStep -Label "service principal(s)" -Kind "AZServicePrincipal" -Suffix "service-principals" -Path "servicePrincipals" -Query @{ '$top' = 999 }
$tenants = Invoke-GraphCollectionStep -Label "tenant object(s)" -Kind "AZTenant" -Suffix "tenants" -Path "organization"
$roles = Invoke-GraphCollectionStep -Label "directory role definition(s)" -Kind "AZRole" -Suffix "directory-roles" -Path "roleManagement/directory/roleDefinitions"

if (-not $SkipRelationships) {
    $roleAssignments = Invoke-GraphCollectionStep -Label "directory role assignment(s)" -Kind "AZRoleAssignment" -Suffix "directory-role-assignments" -Path "roleManagement/directory/roleAssignments" -Query @{ '$top' = 999 }
    $eligibleRoles = Invoke-GraphCollectionStep -Label "eligible role schedule instance(s)" -Kind "AZRoleEligibilityScheduleInstance" -Suffix "role-eligibility-schedule-instances" -Path "roleManagement/directory/roleEligibilityScheduleInstances"
    $policyAssignments = Invoke-GraphCollectionStep -Label "role management policy assignment(s)" -Kind "AZRoleManagementPolicyAssignment" -Suffix "role-management-policy-assignments" -Path "policies/roleManagementPolicyAssignments"

    Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting application owners and federated identity credentials"
    $appOwnerRecords = [System.Collections.Generic.List[object]]::new()
    $ficRecords = [System.Collections.Generic.List[object]]::new()
    $appIndex = 0
    foreach ($app in $applications) {
        $appIndex++
        Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting application relationships for $($app.displayName) [$($app.id)]"
        $owners = Get-GraphCollectionOrEmpty -Label "application owners for $($app.id)" -Path "applications/$($app.id)/owners" -Query @{ '$top' = 99 } -UseBeta
        $ownerItems = foreach ($owner in $owners) {
            [pscustomobject]@{
                appId = $app.id
                owner = $owner
            }
        }
        Add-StepRecord -AllRecords $records -StepRecords $appOwnerRecords -Kind "AZAppOwner" -Data ([pscustomobject]@{
            appId = $app.appId
            owners = @($ownerItems)
        })
        Save-StepProgress -Records $appOwnerRecords -Suffix "application-owners" -CurrentIndex $appIndex -TotalCount (@($applications).Count)

        $fics = Get-GraphCollectionOrEmpty -Label "federated identity credentials for application $($app.id)" -Path "applications/$($app.id)/federatedIdentityCredentials" -Query @{ '$top' = 99 } -UseBeta
        foreach ($fic in $fics) {
            Add-StepRecord -AllRecords $records -StepRecords $ficRecords -Kind "AZFederatedIdentityCredential" -Data ([pscustomobject]@{
                appId = $app.id
                federatedIdentityCredential = $fic
            })
        }

        Save-StepProgress -Records $ficRecords -Suffix "federated-identity-credentials" -CurrentIndex $appIndex -TotalCount (@($applications).Count)
    }
    Save-StepProgress -Records $appOwnerRecords -Suffix "application-owners" -CurrentIndex (@($applications).Count) -TotalCount (@($applications).Count) -Force
    Save-StepProgress -Records $ficRecords -Suffix "federated-identity-credentials" -CurrentIndex (@($applications).Count) -TotalCount (@($applications).Count) -Force

    Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting group owners and members"
    $groupOwnerRecords = [System.Collections.Generic.List[object]]::new()
    $groupMemberRecords = [System.Collections.Generic.List[object]]::new()
    $groupIndex = 0
    foreach ($group in $groups) {
        $groupIndex++
        Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting group relationships for $($group.displayName) [$($group.id)]"
        $owners = Get-GraphCollectionOrEmpty -Label "group owners for $($group.id)" -Path "groups/$($group.id)/owners" -Query @{ '$top' = 999 }
        $ownerItems = foreach ($owner in $owners) {
            [pscustomobject]@{
                groupId = $group.id
                owner = $owner
            }
        }
        Add-StepRecord -AllRecords $records -StepRecords $groupOwnerRecords -Kind "AZGroupOwner" -Data ([pscustomobject]@{
            groupId = $group.id
            owners = @($ownerItems)
        })
        Save-StepProgress -Records $groupOwnerRecords -Suffix "group-owners" -CurrentIndex $groupIndex -TotalCount (@($groups).Count)

        $members = Get-GraphCollectionOrEmpty -Label "group members for $($group.id)" -Path "groups/$($group.id)/members" -Query @{ '$top' = 999 }
        $memberItems = foreach ($member in $members) {
            [pscustomobject]@{
                groupId = $group.id
                member = $member
            }
        }
        Add-StepRecord -AllRecords $records -StepRecords $groupMemberRecords -Kind "AZGroupMember" -Data ([pscustomobject]@{
            groupId = $group.id
            members = @($memberItems)
        })

        Save-StepProgress -Records $groupMemberRecords -Suffix "group-members" -CurrentIndex $groupIndex -TotalCount (@($groups).Count)
    }
    Save-StepProgress -Records $groupOwnerRecords -Suffix "group-owners" -CurrentIndex (@($groups).Count) -TotalCount (@($groups).Count) -Force
    Save-StepProgress -Records $groupMemberRecords -Suffix "group-members" -CurrentIndex (@($groups).Count) -TotalCount (@($groups).Count) -Force

    Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting service principal owners and app role assignments"
    $servicePrincipalOwnerRecords = [System.Collections.Generic.List[object]]::new()
    $appRoleAssignmentRecords = [System.Collections.Generic.List[object]]::new()
    $servicePrincipalIndex = 0
    foreach ($sp in $servicePrincipals) {
        $servicePrincipalIndex++
        Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting service principal relationships for $($sp.displayName) [$($sp.id)]"
        $owners = Get-GraphCollectionOrEmpty -Label "service principal owners for $($sp.id)" -Path "servicePrincipals/$($sp.id)/owners" -Query @{ '$top' = 999 }
        $ownerItems = foreach ($owner in $owners) {
            [pscustomobject]@{
                servicePrincipalId = $sp.id
                owner = $owner
            }
        }
        Add-StepRecord -AllRecords $records -StepRecords $servicePrincipalOwnerRecords -Kind "AZServicePrincipalOwner" -Data ([pscustomobject]@{
            servicePrincipalId = $sp.id
            owners = @($ownerItems)
        })
        Save-StepProgress -Records $servicePrincipalOwnerRecords -Suffix "service-principal-owners" -CurrentIndex $servicePrincipalIndex -TotalCount (@($servicePrincipals).Count)

        $appRoleAssignments = Get-GraphCollectionOrEmpty -Label "app role assignments for service principal $($sp.id)" -Path "servicePrincipals/$($sp.id)/appRoleAssignedTo" -Query @{ '$top' = 999 }
        foreach ($assignment in $appRoleAssignments) {
            Add-StepRecord -AllRecords $records -StepRecords $appRoleAssignmentRecords -Kind "AZAppRoleAssignment" -Data ([pscustomobject]@{
                servicePrincipalId = $sp.id
                appRoleAssignment = $assignment
            })
        }

        Save-StepProgress -Records $appRoleAssignmentRecords -Suffix "app-role-assignments" -CurrentIndex $servicePrincipalIndex -TotalCount (@($servicePrincipals).Count)
    }
    Save-StepProgress -Records $servicePrincipalOwnerRecords -Suffix "service-principal-owners" -CurrentIndex (@($servicePrincipals).Count) -TotalCount (@($servicePrincipals).Count) -Force
    Save-StepProgress -Records $appRoleAssignmentRecords -Suffix "app-role-assignments" -CurrentIndex (@($servicePrincipals).Count) -TotalCount (@($servicePrincipals).Count) -Force
}
else {
    Write-AzureHoundStatus -Stage "AZAD" -Message "Skipping Entra ID relationship, role assignment, and PIM policy collection"
}

Write-AzureHoundStatus -Stage "AZAD" -Message "Finished Entra ID collection with $($records.Count) record(s)"
Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
