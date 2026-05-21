[CmdletBinding()]
param(
    [string] $OutputPath,
    [switch] $SkipRelationships,
    [switch] $ContinueOnError
)

. "$PSScriptRoot/AzCliAzureHound.Common.ps1"

function Get-GraphCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Path,

        [hashtable] $Query = @{},

        [switch] $UseBeta,
        [switch] $ContinueOnError
    )

    $version = if ($UseBeta) { "beta" } else { "v1.0" }
    $uri = "https://graph.microsoft.com/$version/$Path$(ConvertTo-QueryString -Query $Query)"
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
        [object[]] $Items
    )

    foreach ($item in $Items) {
        $Records.Add((New-AzureHoundRecord -Kind $Kind -Data $item))
    }
}

Assert-AzCliAvailable

$records = [System.Collections.Generic.List[object]]::new()

$users = Get-GraphCollection -Path "users" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZUser" -Items $users

$applications = Get-GraphCollection -Path "applications" -Query @{ '$top' = 99 } -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZApp" -Items $applications

$devices = Get-GraphCollection -Path "devices" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZDevice" -Items $devices

$groups = Get-GraphCollection -Path "groups" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZGroup" -Items $groups

$servicePrincipals = Get-GraphCollection -Path "servicePrincipals" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZServicePrincipal" -Items $servicePrincipals

$tenants = Get-GraphCollection -Path "organization" -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZTenant" -Items $tenants

$roles = Get-GraphCollection -Path "roleManagement/directory/roleDefinitions" -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRole" -Items $roles

$roleAssignments = Get-GraphCollection -Path "roleManagement/directory/roleAssignments" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRoleAssignment" -Items $roleAssignments

$eligibleRoles = Get-GraphCollection -Path "roleManagement/directory/roleEligibilityScheduleInstances" -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRoleEligibilityScheduleInstance" -Items $eligibleRoles

$policyAssignments = Get-GraphCollection -Path "policies/roleManagementPolicyAssignments" -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRoleManagementPolicyAssignment" -Items $policyAssignments

if (-not $SkipRelationships) {
    foreach ($app in $applications) {
        $owners = Get-GraphCollection -Path "applications/$($app.id)/owners" -Query @{ '$top' = 99 } -UseBeta -ContinueOnError:$ContinueOnError
        $ownerItems = foreach ($owner in $owners) {
            [pscustomobject]@{
                appId = $app.id
                owner = $owner
            }
        }
        $records.Add((New-AzureHoundRecord -Kind "AZAppOwner" -Data ([pscustomobject]@{
            appId = $app.appId
            owners = @($ownerItems)
        })))

        $fics = Get-GraphCollection -Path "applications/$($app.id)/federatedIdentityCredentials" -Query @{ '$top' = 99 } -UseBeta -ContinueOnError:$ContinueOnError
        foreach ($fic in $fics) {
            $records.Add((New-AzureHoundRecord -Kind "AZFederatedIdentityCredential" -Data ([pscustomobject]@{
                appId = $app.id
                federatedIdentityCredential = $fic
            })))
        }
    }

    foreach ($group in $groups) {
        $owners = Get-GraphCollection -Path "groups/$($group.id)/owners" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
        $ownerItems = foreach ($owner in $owners) {
            [pscustomobject]@{
                groupId = $group.id
                owner = $owner
            }
        }
        $records.Add((New-AzureHoundRecord -Kind "AZGroupOwner" -Data ([pscustomobject]@{
            groupId = $group.id
            owners = @($ownerItems)
        })))

        $members = Get-GraphCollection -Path "groups/$($group.id)/members" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
        $memberItems = foreach ($member in $members) {
            [pscustomobject]@{
                groupId = $group.id
                member = $member
            }
        }
        $records.Add((New-AzureHoundRecord -Kind "AZGroupMember" -Data ([pscustomobject]@{
            groupId = $group.id
            members = @($memberItems)
        })))
    }

    foreach ($sp in $servicePrincipals) {
        $owners = Get-GraphCollection -Path "servicePrincipals/$($sp.id)/owners" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
        $ownerItems = foreach ($owner in $owners) {
            [pscustomobject]@{
                servicePrincipalId = $sp.id
                owner = $owner
            }
        }
        $records.Add((New-AzureHoundRecord -Kind "AZServicePrincipalOwner" -Data ([pscustomobject]@{
            servicePrincipalId = $sp.id
            owners = @($ownerItems)
        })))

        $appRoleAssignments = Get-GraphCollection -Path "servicePrincipals/$($sp.id)/appRoleAssignedTo" -Query @{ '$top' = 999 } -ContinueOnError:$ContinueOnError
        foreach ($assignment in $appRoleAssignments) {
            $records.Add((New-AzureHoundRecord -Kind "AZAppRoleAssignment" -Data ([pscustomobject]@{
                servicePrincipalId = $sp.id
                appRoleAssignment = $assignment
            })))
        }
    }
}

Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
