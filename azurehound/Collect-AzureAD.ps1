[CmdletBinding()]
param(
    [string] $OutputPath,
    [int] $MaxPages,
    [int] $MaxItems,
    [switch] $SkipRelationships,
    [switch] $SkipAzCliCheck,
    [switch] $ContinueOnError
)

. "$PSScriptRoot/AzCliAzureHound.Common.ps1"

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

if (-not $SkipAzCliCheck) {
    Assert-AzCliAvailable
}

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting Entra ID objects"
$records = [System.Collections.Generic.List[object]]::new()

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting users"
$users = Get-GraphCollection -Path "users" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZUser" -Items $users
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($users).Count) user(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting applications"
$applications = Get-GraphCollection -Path "applications" -Query @{ '$top' = 99 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZApp" -Items $applications
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($applications).Count) application(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting devices"
$devices = Get-GraphCollection -Path "devices" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZDevice" -Items $devices
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($devices).Count) device(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting groups"
$groups = Get-GraphCollection -Path "groups" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZGroup" -Items $groups
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($groups).Count) group(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting service principals"
$servicePrincipals = Get-GraphCollection -Path "servicePrincipals" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZServicePrincipal" -Items $servicePrincipals
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($servicePrincipals).Count) service principal(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting tenant organization"
$tenants = Get-GraphCollection -Path "organization" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZTenant" -Items $tenants
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($tenants).Count) tenant object(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting directory role definitions"
$roles = Get-GraphCollection -Path "roleManagement/directory/roleDefinitions" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRole" -Items $roles
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($roles).Count) directory role definition(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting directory role assignments"
$roleAssignments = Get-GraphCollection -Path "roleManagement/directory/roleAssignments" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRoleAssignment" -Items $roleAssignments
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($roleAssignments).Count) directory role assignment(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting eligible role schedule instances"
$eligibleRoles = Get-GraphCollection -Path "roleManagement/directory/roleEligibilityScheduleInstances" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRoleEligibilityScheduleInstance" -Items $eligibleRoles
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($eligibleRoles).Count) eligible role schedule instance(s)"

Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting role management policy assignments"
$policyAssignments = Get-GraphCollection -Path "policies/roleManagementPolicyAssignments" -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
Add-CollectionRecords -Records $records -Kind "AZRoleManagementPolicyAssignment" -Items $policyAssignments
Write-AzureHoundStatus -Stage "AZAD" -Message "Collected $(@($policyAssignments).Count) role management policy assignment(s)"

if (-not $SkipRelationships) {
    Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting application owners and federated identity credentials"
    foreach ($app in $applications) {
        Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting application relationships for $($app.displayName) [$($app.id)]"
        $owners = Get-GraphCollection -Path "applications/$($app.id)/owners" -Query @{ '$top' = 99 } -UseBeta -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
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

        $fics = Get-GraphCollection -Path "applications/$($app.id)/federatedIdentityCredentials" -Query @{ '$top' = 99 } -UseBeta -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
        foreach ($fic in $fics) {
            $records.Add((New-AzureHoundRecord -Kind "AZFederatedIdentityCredential" -Data ([pscustomobject]@{
                appId = $app.id
                federatedIdentityCredential = $fic
            })))
        }
    }

    Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting group owners and members"
    foreach ($group in $groups) {
        Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting group relationships for $($group.displayName) [$($group.id)]"
        $owners = Get-GraphCollection -Path "groups/$($group.id)/owners" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
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

        $members = Get-GraphCollection -Path "groups/$($group.id)/members" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
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

    Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting service principal owners and app role assignments"
    foreach ($sp in $servicePrincipals) {
        Write-AzureHoundStatus -Stage "AZAD" -Message "Collecting service principal relationships for $($sp.displayName) [$($sp.id)]"
        $owners = Get-GraphCollection -Path "servicePrincipals/$($sp.id)/owners" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
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

        $appRoleAssignments = Get-GraphCollection -Path "servicePrincipals/$($sp.id)/appRoleAssignedTo" -Query @{ '$top' = 999 } -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError
        foreach ($assignment in $appRoleAssignments) {
            $records.Add((New-AzureHoundRecord -Kind "AZAppRoleAssignment" -Data ([pscustomobject]@{
                servicePrincipalId = $sp.id
                appRoleAssignment = $assignment
            })))
        }
    }
}
else {
    Write-AzureHoundStatus -Stage "AZAD" -Message "Skipping Entra ID relationship collection"
}

Write-AzureHoundStatus -Stage "AZAD" -Message "Finished Entra ID collection with $($records.Count) record(s)"
Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
