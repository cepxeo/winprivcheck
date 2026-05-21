function Write-AzureHoundStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Message,

        [string] $Stage = "INFO"
    )

    $timestamp = Get-Date -Format "HH:mm:ss"
    Write-Host ("[{0}] [{1}] {2}" -f $timestamp, $Stage, $Message) -ForegroundColor Cyan
}

function Assert-AzCliAvailable {
    Write-AzureHoundStatus -Stage "CHECK" -Message "Checking Azure CLI availability"
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI (az) was not found on PATH."
    }

    Write-AzureHoundStatus -Stage "CHECK" -Message "Checking active Azure CLI account"
    $azAccountError = [System.IO.Path]::GetTempFileName()
    try {
        $null = az account show --only-show-errors 2>$azAccountError
        $accountError = Get-Content -Path $azAccountError -Raw -ErrorAction SilentlyContinue
    }
    finally {
        Remove-Item -Path $azAccountError -Force -ErrorAction SilentlyContinue
    }

    if ($LASTEXITCODE -ne 0) {
        $message = "Azure CLI is not logged in or cannot read the active account. Run 'az login' before collecting data."
        if (-not [string]::IsNullOrWhiteSpace($accountError)) {
            $message = "$message`naz account show: $($accountError.Trim())"
        }
        throw $message
    }
    Write-AzureHoundStatus -Stage "CHECK" -Message "Azure CLI account is available"
}

function ConvertTo-QueryString {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Query
    )

    $pairs = foreach ($key in $Query.Keys) {
        if ($null -ne $Query[$key] -and "$($Query[$key])" -ne "") {
            "{0}={1}" -f [uri]::EscapeDataString($key), [uri]::EscapeDataString("$($Query[$key])")
        }
    }

    if ($pairs.Count -eq 0) {
        return ""
    }

    return "?" + ($pairs -join "&")
}

function Invoke-AzCliJson {
    param(
        [Parameter(Mandatory = $true)]
        [string] $CommandName,

        [Parameter(Mandatory = $true)]
        [scriptblock] $ScriptBlock,

        [switch] $ContinueOnError
    )

    $stderrPath = [System.IO.Path]::GetTempFileName()
    try {
        $json = & $ScriptBlock 2>$stderrPath
        $stderr = Get-Content -Path $stderrPath -Raw -ErrorAction SilentlyContinue
        $stdout = ($json | ForEach-Object { [string] $_ }) -join "`n"
        if ($LASTEXITCODE -ne 0) {
            $details = [System.Collections.Generic.List[string]]::new()
            if (-not [string]::IsNullOrWhiteSpace($stderr)) {
                $details.Add($stderr.Trim())
            }
            if (-not [string]::IsNullOrWhiteSpace($stdout)) {
                $details.Add($stdout.Trim())
            }

            $message = "$CommandName failed with exit code $LASTEXITCODE"
            if ($details.Count -gt 0) {
                $message = "$message`: $($details -join "`n")"
            }
            throw $message
        }
        if ([string]::IsNullOrWhiteSpace($stdout)) {
            return $null
        }
        try {
            return $json | ConvertFrom-Json
        }
        catch {
            throw "$CommandName returned invalid JSON: $($stdout.Trim())"
        }
    }
    catch {
        if ($ContinueOnError) {
            Write-Warning ("{0}: {1}" -f $CommandName, $_.Exception.Message)
            return $null
        }
        throw
    }
    finally {
        Remove-Item -Path $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-AzRestCollection {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Uri,

        [switch] $ContinueOnError
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    $page = 1

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        Write-AzureHoundStatus -Stage "REST" -Message "Requesting page $page`: $next"
        $response = Invoke-AzCliJson -CommandName "az rest $next" -ContinueOnError:$ContinueOnError -ScriptBlock {
            az rest --method get --uri $next --only-show-errors
        }

        if ($null -eq $response) {
            break
        }

        if ($null -ne $response.value) {
            foreach ($item in @($response.value)) {
                $items.Add($item)
            }
        }
        else {
            $items.Add($response)
        }

        if ($response.PSObject.Properties.Name -contains "@odata.nextLink") {
            $next = $response."@odata.nextLink"
        }
        elseif ($response.PSObject.Properties.Name -contains "nextLink") {
            $next = $response.nextLink
        }
        else {
            $next = $null
        }

        Write-AzureHoundStatus -Stage "REST" -Message "Collected $($items.Count) item(s) so far"
        $page++
    }

    return $items.ToArray()
}

function New-AzureHoundRecord {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Kind,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object] $Data
    )

    [pscustomobject]@{
        kind = $Kind
        data = $Data
    }
}

function Get-RoleDefinitionIdLeaf {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string] $RoleDefinitionId
    )

    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) {
        return ""
    }

    return ($RoleDefinitionId.TrimEnd("/") -split "/")[-1].ToLowerInvariant()
}

function Get-AzureHoundRoleRelationshipKind {
    param(
        [Parameter(Mandatory = $true)]
        [string] $ScopeKind,

        [Parameter(Mandatory = $true)]
        [string] $RoleDefinitionId
    )

    $roleId = Get-RoleDefinitionIdLeaf -RoleDefinitionId $RoleDefinitionId
    $map = @{
        "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" = "Owner"
        "b24988ac-6180-42a0-ab88-20f7382dd24c" = "Contributor"
        "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9" = "UserAccessAdmin"
    }

    if ($ScopeKind -eq "KeyVault" -and $roleId -eq "f25e0fa2-a7c8-4377-a976-54943a77a395") {
        return "AZKeyVaultKVContributor"
    }
    if ($ScopeKind -eq "VM" -and $roleId -eq "4f8fab4f-1852-4a58-a46a-8eaf358af14a") {
        return "AZVMAvereContributor"
    }
    if ($ScopeKind -eq "VM" -and $roleId -eq "9980e02c-c2be-4d73-94e8-173b1dc7cf3c") {
        return "AZVMVMContributor"
    }
    if ($ScopeKind -eq "VM" -and $roleId -eq "1c0163c0-47e6-4577-8991-ea5c82e286e4") {
        return "AZVMAdminLogin"
    }

    if (-not $map.ContainsKey($roleId)) {
        return $null
    }

    switch ($ScopeKind) {
        "ManagementGroup" { return "AZManagementGroup$($map[$roleId])" }
        "Subscription" { return "AZSubscription$($map[$roleId])" }
        "ResourceGroup" { return "AZResourceGroup$($map[$roleId])" }
        "KeyVault" { return "AZKeyVault$($map[$roleId])" }
        "VM" { return "AZVM$($map[$roleId])" }
        default { return $null }
    }
}

function Add-AzureHoundRoleAssignmentRecords {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[object]] $Records,

        [Parameter(Mandatory = $true)]
        [string] $ScopeKind,

        [Parameter(Mandatory = $true)]
        [string] $RecordKind,

        [Parameter(Mandatory = $true)]
        [string] $ContainerPropertyName,

        [Parameter(Mandatory = $true)]
        [string] $ScopeId,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object[]] $Assignments
    )

    $roleItems = [System.Collections.Generic.List[object]]::new()
    foreach ($assignment in $Assignments) {
        $item = [pscustomobject]@{
            roleAssignment = $assignment
        }
        $item | Add-Member -NotePropertyName $ContainerPropertyName -NotePropertyValue $ScopeId
        $roleItems.Add($item)

        $relationshipKind = Get-AzureHoundRoleRelationshipKind -ScopeKind $ScopeKind -RoleDefinitionId $assignment.properties.roleDefinitionId
        if ($relationshipKind) {
            $relationship = [pscustomobject]@{
                roleAssignment = $assignment
            }
            $relationship | Add-Member -NotePropertyName $ContainerPropertyName -NotePropertyValue $ScopeId
            $Records.Add((New-AzureHoundRecord -Kind $relationshipKind -Data $relationship))
        }
    }

    $container = [pscustomobject]@{}
    $container | Add-Member -NotePropertyName $ContainerPropertyName -NotePropertyValue $ScopeId
    $container | Add-Member -NotePropertyName "roleAssignments" -NotePropertyValue @($roleItems)
    $Records.Add((New-AzureHoundRecord -Kind $RecordKind -Data $container))
}

function Write-AzureHoundOutput {
    param(
        [Parameter(Mandatory = $true)]
        [object] $Records,

        [string] $OutputPath
    )

    $items = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $Records) {
        foreach ($record in $Records) {
            $items.Add($record)
        }
    }

    $document = [ordered]@{
        data = $items.ToArray()
        meta = [ordered]@{
            type = "azure"
            version = 5
            count = $items.Count
        }
    }

    $json = $document | ConvertTo-Json -Depth 100
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-AzureHoundStatus -Stage "OUTPUT" -Message "Writing $($items.Count) record(s) to stdout"
        $json
    }
    else {
        $parent = Split-Path -Parent $OutputPath
        if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path $parent)) {
            Write-AzureHoundStatus -Stage "OUTPUT" -Message "Creating output directory $parent"
            New-Item -ItemType Directory -Path $parent -Force | Out-Null
        }
        Write-AzureHoundStatus -Stage "OUTPUT" -Message "Writing $($items.Count) record(s) to $OutputPath"
        Set-Content -Path $OutputPath -Value $json -Encoding UTF8
    }
}
