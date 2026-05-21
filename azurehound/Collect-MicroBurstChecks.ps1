[CmdletBinding()]
param(
    [string] $OutputPath = "microburst-checks.json",
    [string[]] $SubscriptionId,
    [int] $MaxPages,
    [int] $MaxItems,
    [switch] $IncludeSecretValues,
    [switch] $ContinueOnError
)

. "$PSScriptRoot/AzCliAzureHound.Common.ps1"

Assert-AzCliAvailable

$records = [System.Collections.Generic.List[object]]::new()

function Invoke-AzRestJson {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [string] $Uri,

        [switch] $ContinueOnError
    )

    Invoke-AzCliJson -CommandName $Name -Arguments @("rest", "--method", $Method, "--uri", $Uri, "--only-show-errors") -ContinueOnError:$ContinueOnError
}

function Invoke-AzRestJsonSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [string] $Uri
    )

    try {
        return Invoke-AzRestJson -Name $Name -Method $Method -Uri $Uri -ContinueOnError
    }
    catch {
        Write-Warning ("Skipping {0}: {1}" -f $Name, $_.Exception.Message)
        return $null
    }
}

function Invoke-AzCliJsonSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string[]] $Arguments
    )

    try {
        return Invoke-AzCliJson -CommandName $Name -Arguments $Arguments -ContinueOnError
    }
    catch {
        Write-Warning ("Skipping {0}: {1}" -f $Name, $_.Exception.Message)
        return $null
    }
}

function Invoke-BearerRestJsonSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Uri,

        [Parameter(Mandatory = $true)]
        [string] $AccessToken
    )

    try {
        return Invoke-RestMethod -Method Get -Uri $Uri -Headers @{ Authorization = "Bearer $AccessToken" }
    }
    catch {
        Write-Warning ("Skipping {0}: {1}" -f $Name, $_.Exception.Message)
        return $null
    }
}

function Invoke-BearerRestCollectionSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Uri,

        [Parameter(Mandatory = $true)]
        [string] $AccessToken
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $page = 0
    $nextUri = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        if ($MaxPages -gt 0 -and $page -ge $MaxPages) {
            break
        }

        $page++
        Write-AzureHoundStatus -Stage "MB" -Message "Requesting $Name page $page"
        $response = Invoke-BearerRestJsonSafe -Name $Name -Uri $nextUri -AccessToken $AccessToken
        if ($null -eq $response) {
            break
        }

        foreach ($item in @($response.value)) {
            $items.Add($item)
            if ($MaxItems -gt 0 -and $items.Count -ge $MaxItems) {
                return @($items)
            }
        }

        $nextUri = $response.'odata.nextLink'
        if ([string]::IsNullOrWhiteSpace($nextUri)) {
            $nextUri = $response.'@odata.nextLink'
        }
    }

    return @($items)
}

function Invoke-AzRestCollectionSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Name,

        [Parameter(Mandatory = $true)]
        [string] $Uri
    )

    try {
        return @(Invoke-AzRestCollection -Uri $Uri -MaxPages $MaxPages -MaxItems $MaxItems -ContinueOnError:$ContinueOnError)
    }
    catch {
        Write-Warning ("Skipping {0}: {1}" -f $Name, $_.Exception.Message)
        return @()
    }
}

function Add-Record {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Kind,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object] $Data
    )

    $record = New-AzureHoundRecord -Kind $Kind -Data $Data
    $records.Add($record)
    return $record
}

function Write-StepOutput {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Suffix,

        [Parameter(Mandatory = $true)]
        [object] $StepRecords
    )

    $fileSuffix = if ([string]::IsNullOrWhiteSpace($script:CurrentSubscriptionId)) { $Suffix } else { "$script:CurrentSubscriptionId-$Suffix" }
    Write-AzureHoundPartOutput -Records $StepRecords -OutputPath $OutputPath -Suffix $fileSuffix
}

function Get-ResourceGroupFromId {
    param([string] $ResourceId)

    $parts = $ResourceId -split "/"
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i] -eq "resourceGroups" -and ($i + 1) -lt $parts.Count) {
            return $parts[$i + 1]
        }
    }
    return $null
}

function Test-InterestingSettingName {
    param([string] $Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    return ($Name -match '(?i)(secret|password|passwd|pwd|token|client[_-]?secret|connection|string|key|sas|credential|cert|thumbprint)')
}

function ConvertTo-SafeValue {
    param([object] $Value)

    if ($IncludeSecretValues) {
        return $Value
    }
    if ($null -eq $Value) {
        return $null
    }
    return "[redacted]"
}

function Get-ResourceNameFromId {
    param([string] $ResourceId)

    if ([string]::IsNullOrWhiteSpace($ResourceId)) {
        return $null
    }
    return ($ResourceId.TrimEnd([char]"/") -split "/")[-1]
}

function ConvertTo-Base64Sha256 {
    param([AllowNull()][string] $Content)

    if ($null -eq $Content) {
        $Content = ""
    }

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [Convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Content)))
    }
    finally {
        $sha256.Dispose()
    }
}

function ConvertTo-Base64HmacSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string] $Secret,

        [Parameter(Mandatory = $true)]
        [string] $Content
    )

    $hmac = [System.Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($Secret))
    try {
        return [Convert]::ToBase64String($hmac.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Content)))
    }
    finally {
        $hmac.Dispose()
    }
}

function New-AppConfigurationHeaders {
    param(
        [Parameter(Mandatory = $true)]
        [System.Uri] $Uri,

        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [string] $AccessKeyId,

        [Parameter(Mandatory = $true)]
        [string] $AccessKeyValue
    )

    $verb = $Method.ToUpperInvariant()
    $utcNow = (Get-Date).ToUniversalTime().ToString("R", [Globalization.DateTimeFormatInfo]::InvariantInfo)
    $contentHash = ConvertTo-Base64Sha256 -Content ""
    $signedHeaders = "x-ms-date;host;x-ms-content-sha256"
    $stringToSign = $verb + "`n" + $Uri.PathAndQuery + "`n" + $utcNow + ";" + $Uri.Authority + ";" + $contentHash
    $signature = ConvertTo-Base64HmacSha256 -Secret $AccessKeyValue -Content $stringToSign

    return @{
        "x-ms-date" = $utcNow
        "Host" = $Uri.Authority
        "x-ms-content-sha256" = $contentHash
        "Authorization" = "HMAC-SHA256 Credential=$AccessKeyId&SignedHeaders=$signedHeaders&Signature=$signature"
    }
}

function Invoke-AppConfigurationCollectionSafe {
    param(
        [Parameter(Mandatory = $true)]
        [string] $StoreName,

        [Parameter(Mandatory = $true)]
        [string] $Endpoint,

        [Parameter(Mandatory = $true)]
        [object] $AccessKey
    )

    $items = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $AccessKey -or [string]::IsNullOrWhiteSpace($AccessKey.id) -or [string]::IsNullOrWhiteSpace($AccessKey.value)) {
        return @()
    }

    $baseEndpoint = $Endpoint
    if ([string]::IsNullOrWhiteSpace($baseEndpoint)) {
        $baseEndpoint = "https://$StoreName.azconfig.io"
    }
    $baseUri = [System.Uri]::new($baseEndpoint.TrimEnd([char]"/") + "/")
    $nextLink = "/kv?api-version=1.0"
    $page = 0

    while (-not [string]::IsNullOrWhiteSpace($nextLink)) {
        if ($MaxPages -gt 0 -and $page -ge $MaxPages) {
            break
        }

        $uri = if ([System.Uri]::IsWellFormedUriString($nextLink, [System.UriKind]::Absolute)) {
            [System.Uri]::new($nextLink)
        }
        else {
            [System.Uri]::new($baseUri, $nextLink.TrimStart([char]"/"))
        }

        try {
            $page++
            Write-AzureHoundStatus -Stage "MB" -Message "Requesting App Configuration page $page from $StoreName"
            $headers = New-AppConfigurationHeaders -Uri $uri -Method "GET" -AccessKeyId $AccessKey.id -AccessKeyValue $AccessKey.value
            $response = Invoke-RestMethod -Method Get -Uri $uri -Headers $headers

            foreach ($item in @($response.items)) {
                $items.Add($item)
                if ($MaxItems -gt 0 -and $items.Count -ge $MaxItems) {
                    return @($items)
                }
            }

            $nextLink = $response.'@nextLink'
        }
        catch {
            Write-Warning ("Skipping App Configuration values for {0}: {1}" -f $StoreName, $_.Exception.Message)
            break
        }
    }

    return @($items)
}

function Get-SubscriptionsToCollect {
    $all = Invoke-AzRestCollectionSafe -Name "subscriptions" -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01"
    if (@($SubscriptionId).Count -eq 0) {
        return @($all)
    }

    $selected = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $SubscriptionId) {
        $null = $selected.Add($id.Trim([char]"/").Split("/")[-1])
    }

    return @($all | Where-Object { $selected.Contains($_.subscriptionId) })
}

$subscriptions = Get-SubscriptionsToCollect
Write-AzureHoundStatus -Stage "MB" -Message "Running MicroBurst-inspired checks across $(@($subscriptions).Count) subscription(s)"

foreach ($subscription in $subscriptions) {
    $sid = $subscription.subscriptionId
    $script:CurrentSubscriptionId = $sid
    Write-AzureHoundStatus -Stage "MB" -Message "Collecting checks for subscription $sid"

    $subscriptionRecords = [System.Collections.Generic.List[object]]::new()
    $subscriptionRecords.Add((Add-Record -Kind "MBSubscription" -Data $subscription))
    Write-StepOutput -Suffix "subscriptions" -StepRecords $subscriptionRecords

    $vaultRecords = [System.Collections.Generic.List[object]]::new()
    $vaults = Invoke-AzRestCollectionSafe -Name "key vaults" -Uri "https://management.azure.com/subscriptions/$sid/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01"
    foreach ($vault in $vaults) {
        $vaultName = $vault.name
        Write-AzureHoundStatus -Stage "MB" -Message "Checking Key Vault $vaultName"
        $secretList = Invoke-AzCliJson -CommandName "az keyvault secret list $vaultName" -Arguments @("keyvault", "secret", "list", "--vault-name", $vaultName, "--only-show-errors") -ContinueOnError
        $keyList = Invoke-AzCliJson -CommandName "az keyvault key list $vaultName" -Arguments @("keyvault", "key", "list", "--vault-name", $vaultName, "--only-show-errors") -ContinueOnError
        $certList = Invoke-AzCliJson -CommandName "az keyvault certificate list $vaultName" -Arguments @("keyvault", "certificate", "list", "--vault-name", $vaultName, "--only-show-errors") -ContinueOnError

        $secretValues = @()
        $certificateSecretValues = @()
        if ($IncludeSecretValues) {
            foreach ($secret in @($secretList)) {
                $secretName = $secret.name
                $secretValue = Invoke-AzCliJsonSafe -Name "az keyvault secret show $vaultName/$secretName" -Arguments @("keyvault", "secret", "show", "--vault-name", $vaultName, "--name", $secretName, "--only-show-errors")
                if ($null -ne $secretValue) {
                    $secretValues += [pscustomobject]@{
                        name = $secretName
                        id = $secretValue.id
                        contentType = $secretValue.contentType
                        attributes = $secretValue.attributes
                        value = $secretValue.value
                    }
                }
            }

            foreach ($certificate in @($certList)) {
                $certificateName = $certificate.name
                $certificateSecret = Invoke-AzCliJsonSafe -Name "az keyvault secret show certificate $vaultName/$certificateName" -Arguments @("keyvault", "secret", "show", "--vault-name", $vaultName, "--name", $certificateName, "--only-show-errors")
                if ($null -ne $certificateSecret) {
                    $certificateSecretValues += [pscustomobject]@{
                        name = $certificateName
                        id = $certificateSecret.id
                        contentType = $certificateSecret.contentType
                        attributes = $certificateSecret.attributes
                        value = $certificateSecret.value
                    }
                }
            }
        }

        $data = [pscustomobject]@{
            subscriptionId = $sid
            id = $vault.id
            name = $vaultName
            location = $vault.location
            tenantId = $vault.properties.tenantId
            enableRbacAuthorization = $vault.properties.enableRbacAuthorization
            enablePurgeProtection = $vault.properties.enablePurgeProtection
            enableSoftDelete = $vault.properties.enableSoftDelete
            publicNetworkAccess = $vault.properties.publicNetworkAccess
            accessPolicies = $vault.properties.accessPolicies
            readableSecrets = @($secretList).Count
            readableKeys = @($keyList).Count
            readableCertificates = @($certList).Count
            secrets = ConvertTo-SafeValue -Value $secretValues
            keys = $keyList
            certificates = $certList
            certificateSecrets = ConvertTo-SafeValue -Value $certificateSecretValues
        }
        $vaultRecords.Add((Add-Record -Kind "MBKeyVaultCheck" -Data $data))
    }
    Write-StepOutput -Suffix "key-vaults" -StepRecords $vaultRecords

    $automationRecords = [System.Collections.Generic.List[object]]::new()
    $automationAccounts = Invoke-AzRestCollectionSafe -Name "automation accounts" -Uri "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Automation/automationAccounts?api-version=2023-11-01"
    foreach ($account in $automationAccounts) {
        $rg = Get-ResourceGroupFromId -ResourceId $account.id
        $name = $account.name
        Write-AzureHoundStatus -Stage "MB" -Message "Checking Automation Account $name"
        $base = "https://management.azure.com/subscriptions/$sid/resourceGroups/$rg/providers/Microsoft.Automation/automationAccounts/$name"
        $connections = Invoke-AzRestCollectionSafe -Name "automation connections for $name" -Uri "$base/connections?api-version=2019-06-01"
        $credentials = Invoke-AzRestCollectionSafe -Name "automation credentials for $name" -Uri "$base/credentials?api-version=2019-06-01"
        $certificates = Invoke-AzRestCollectionSafe -Name "automation certificates for $name" -Uri "$base/certificates?api-version=2019-06-01"
        $variables = Invoke-AzRestCollectionSafe -Name "automation variables for $name" -Uri "$base/variables?api-version=2019-06-01"
        $runbooks = Invoke-AzRestCollectionSafe -Name "automation runbooks for $name" -Uri "$base/runbooks?api-version=2019-06-01"
        $modules = Invoke-AzRestCollectionSafe -Name "automation modules for $name" -Uri "$base/modules?api-version=2019-06-01"
        $powershell7Modules = Invoke-AzRestCollectionSafe -Name "automation PowerShell 7 modules for $name" -Uri "$base/powershell7Modules?api-version=2019-06-01"
        $powershell72Modules = Invoke-AzRestCollectionSafe -Name "automation PowerShell 7.2 modules for $name" -Uri "$base/powershell72Modules?api-version=2019-06-01"
        $python2Packages = Invoke-AzRestCollectionSafe -Name "automation Python 2 packages for $name" -Uri "$base/python2Packages?api-version=2018-06-30"
        $python3Packages = Invoke-AzRestCollectionSafe -Name "automation Python 3 packages for $name" -Uri "$base/python3Packages?api-version=2018-06-30"
        $runtimeEnvironments = Invoke-AzRestCollectionSafe -Name "automation runtime environments for $name" -Uri "$base/runtimeEnvironments?api-version=2023-05-15-preview"
        $hybridGroups = Invoke-AzRestCollectionSafe -Name "hybrid worker groups for $name" -Uri "$base/hybridRunbookWorkerGroups?api-version=2023-11-01"
        $data = [pscustomobject]@{
            subscriptionId = $sid
            id = $account.id
            name = $name
            resourceGroup = $rg
            identity = $account.identity
            connectionCount = @($connections).Count
            credentialCount = @($credentials).Count
            certificateCount = @($certificates).Count
            variableCount = @($variables).Count
            runbookCount = @($runbooks).Count
            customModules = @($modules | Where-Object { $_.properties.isGlobal -ne $true })
            powershell7Modules = $powershell7Modules
            powershell72Modules = $powershell72Modules
            python2Packages = $python2Packages
            python3Packages = $python3Packages
            runtimeEnvironments = $runtimeEnvironments
            hybridWorkerGroups = $hybridGroups
            connections = $connections
            credentials = $credentials
            certificates = $certificates
            variables = $variables
            runbooks = $runbooks
        }
        $automationRecords.Add((Add-Record -Kind "MBAutomationCheck" -Data $data))
    }
    Write-StepOutput -Suffix "automation-accounts" -StepRecords $automationRecords

    $webAppRecords = [System.Collections.Generic.List[object]]::new()
    $sites = Invoke-AzRestCollectionSafe -Name "web apps and function apps" -Uri "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Web/sites?api-version=2022-03-01"
    foreach ($site in $sites) {
        $rg = Get-ResourceGroupFromId -ResourceId $site.id
        $name = $site.name
        Write-AzureHoundStatus -Stage "MB" -Message "Checking App Service $name"
        $base = "https://management.azure.com/subscriptions/$sid/resourceGroups/$rg/providers/Microsoft.Web/sites/$name"
        $appSettingsResponse = Invoke-AzRestJson -Name "app settings for $name" -Method "post" -Uri "$base/config/appsettings/list?api-version=2022-03-01" -ContinueOnError
        $authSettings = Invoke-AzRestJson -Name "auth settings for $name" -Method "get" -Uri "$base/config/authsettingsV2/list?api-version=2022-03-01" -ContinueOnError
        $publishingProfile = $null
        $functionHostKeys = $null
        $functionKeys = @()
        if ($IncludeSecretValues) {
            $publishingProfile = Invoke-AzRestJsonSafe -Name "publishing profile for $name" -Method "post" -Uri "$base/publishxml?api-version=2022-03-01"
            if ($site.kind -match "functionapp") {
                $functionHostKeys = Invoke-AzRestJsonSafe -Name "function host keys for $name" -Method "post" -Uri "$base/host/default/listKeys?api-version=2022-03-01"
                $functions = Invoke-AzRestCollectionSafe -Name "functions for $name" -Uri "$base/functions?api-version=2022-03-01"
                foreach ($function in $functions) {
                    $functionName = Get-ResourceNameFromId -ResourceId $function.id
                    $keys = Invoke-AzRestJsonSafe -Name "function keys for $name/$functionName" -Method "post" -Uri "$base/functions/$functionName/listKeys?api-version=2022-03-01"
                    if ($null -ne $keys) {
                        $functionKeys += [pscustomobject]@{
                            functionName = $functionName
                            keys = $keys
                        }
                    }
                }
            }
        }

        $interestingSettings = @()
        if ($null -ne $appSettingsResponse -and $null -ne $appSettingsResponse.properties) {
            foreach ($property in @($appSettingsResponse.properties.PSObject.Properties)) {
                if (Test-InterestingSettingName -Name $property.Name) {
                    $interestingSettings += [pscustomobject]@{
                        name = $property.Name
                        value = ConvertTo-SafeValue -Value $property.Value
                    }
                }
            }
        }

        $data = [pscustomobject]@{
            subscriptionId = $sid
            id = $site.id
            name = $name
            resourceGroup = $rg
            kind = $site.kind
            identity = $site.identity
            defaultHostName = $site.properties.defaultHostName
            state = $site.properties.state
            authEnabled = $authSettings.properties.platform.enabled
            authIdentityProviders = $authSettings.properties.identityProviders
            interestingAppSettings = $interestingSettings
            publishingProfile = ConvertTo-SafeValue -Value $publishingProfile
            functionHostKeys = ConvertTo-SafeValue -Value $functionHostKeys
            functionKeys = ConvertTo-SafeValue -Value $functionKeys
        }
        $webAppRecords.Add((Add-Record -Kind "MBAppServiceCheck" -Data $data))
    }
    Write-StepOutput -Suffix "app-services" -StepRecords $webAppRecords

    $storageRecords = [System.Collections.Generic.List[object]]::new()
    $storageAccounts = Invoke-AzRestCollectionSafe -Name "storage accounts" -Uri "https://management.azure.com/subscriptions/$sid/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
    foreach ($account in $storageAccounts) {
        $rg = Get-ResourceGroupFromId -ResourceId $account.id
        $name = $account.name
        Write-AzureHoundStatus -Stage "MB" -Message "Checking Storage Account $name"
        $keys = $null
        if ($IncludeSecretValues) {
            $keys = Invoke-AzRestJson -Name "storage keys for $name" -Method "post" -Uri "https://management.azure.com/subscriptions/$sid/resourceGroups/$rg/providers/Microsoft.Storage/storageAccounts/$name/listKeys?api-version=2023-01-01" -ContinueOnError
        }
        $data = [pscustomobject]@{
            subscriptionId = $sid
            id = $account.id
            name = $name
            resourceGroup = $rg
            kind = $account.kind
            sku = $account.sku
            allowBlobPublicAccess = $account.properties.allowBlobPublicAccess
            allowSharedKeyAccess = $account.properties.allowSharedKeyAccess
            publicNetworkAccess = $account.properties.publicNetworkAccess
            minimumTlsVersion = $account.properties.minimumTlsVersion
            keys = ConvertTo-SafeValue -Value $keys
        }
        $storageRecords.Add((Add-Record -Kind "MBStorageCheck" -Data $data))
    }
    Write-StepOutput -Suffix "storage-accounts" -StepRecords $storageRecords

    $containerRegistryRecords = [System.Collections.Generic.List[object]]::new()
    $registries = Invoke-AzRestCollectionSafe -Name "container registries" -Uri "https://management.azure.com/subscriptions/$sid/providers/Microsoft.ContainerRegistry/registries?api-version=2023-01-01-preview"
    foreach ($registry in $registries) {
        $rg = Get-ResourceGroupFromId -ResourceId $registry.id
        $name = $registry.name
        Write-AzureHoundStatus -Stage "MB" -Message "Checking Container Registry $name"
        $credentials = $null
        if ($IncludeSecretValues) {
            $credentials = Invoke-AzRestJson -Name "ACR credentials for $name" -Method "post" -Uri "https://management.azure.com/subscriptions/$sid/resourceGroups/$rg/providers/Microsoft.ContainerRegistry/registries/$name/listCredentials?api-version=2023-01-01-preview" -ContinueOnError
        }
        $data = [pscustomobject]@{
            subscriptionId = $sid
            id = $registry.id
            name = $name
            resourceGroup = $rg
            loginServer = $registry.properties.loginServer
            adminUserEnabled = $registry.properties.adminUserEnabled
            publicNetworkAccess = $registry.properties.publicNetworkAccess
            networkRuleBypassOptions = $registry.properties.networkRuleBypassOptions
            identity = $registry.identity
            credentials = ConvertTo-SafeValue -Value $credentials
        }
        $containerRegistryRecords.Add((Add-Record -Kind "MBContainerRegistryCheck" -Data $data))
    }
    Write-StepOutput -Suffix "container-registries" -StepRecords $containerRegistryRecords

    $managedIdentityRecords = [System.Collections.Generic.List[object]]::new()
    $resourceTypes = @(
        "Microsoft.ManagedIdentity/userAssignedIdentities",
        "Microsoft.Compute/virtualMachines",
        "Microsoft.ContainerService/managedClusters",
        "Microsoft.LoadTestService/loadTests",
        "Microsoft.MachineLearningServices/workspaces",
        "Microsoft.App/containerApps",
        "Microsoft.HybridCompute/machines"
    )
    foreach ($resourceType in $resourceTypes) {
        $encodedType = [uri]::EscapeDataString("resourceType eq '$resourceType'")
        $resources = Invoke-AzRestCollectionSafe -Name "$resourceType resources" -Uri "https://management.azure.com/subscriptions/$sid/resources?`$filter=$encodedType&api-version=2021-04-01"
        foreach ($resource in $resources) {
            $extractedSecrets = $null
            if ($IncludeSecretValues) {
                if ($resourceType -eq "Microsoft.ContainerService/managedClusters") {
                    $extractedSecrets = [pscustomobject]@{
                        clusterUserCredential = Invoke-AzRestJsonSafe -Name "AKS user kubeconfig for $($resource.name)" -Method "post" -Uri "$($resource.id)/listClusterUserCredential?api-version=2023-05-01"
                        clusterAdminCredential = Invoke-AzRestJsonSafe -Name "AKS admin kubeconfig for $($resource.name)" -Method "post" -Uri "$($resource.id)/listClusterAdminCredential?api-version=2023-05-01"
                    }
                }
                elseif ($resourceType -eq "Microsoft.App/containerApps") {
                    $extractedSecrets = [pscustomobject]@{
                        secrets = Invoke-AzRestJsonSafe -Name "Container App secrets for $($resource.name)" -Method "post" -Uri "$($resource.id)/listSecrets?api-version=2023-05-01"
                    }
                }
            }

            if ($resource.identity -or $resourceType -eq "Microsoft.ManagedIdentity/userAssignedIdentities") {
                $managedIdentityRecords.Add((Add-Record -Kind "MBManagedIdentitySurface" -Data ([pscustomobject]@{
                    subscriptionId = $sid
                    id = $resource.id
                    name = $resource.name
                    type = $resource.type
                    location = $resource.location
                    identity = $resource.identity
                    properties = $resource.properties
                    extractedSecrets = ConvertTo-SafeValue -Value $extractedSecrets
                })))
            }
        }
    }
    Write-StepOutput -Suffix "managed-identity-surfaces" -StepRecords $managedIdentityRecords

    $otherSecretSurfaceRecords = [System.Collections.Generic.List[object]]::new()
    $secretSurfaceTypes = @(
        @{ Type = "Microsoft.DocumentDB/databaseAccounts"; ApiVersion = "2023-04-15"; Suffix = "cosmos-db" },
        @{ Type = "Microsoft.ServiceBus/namespaces"; ApiVersion = "2022-10-01-preview"; Suffix = "service-bus" },
        @{ Type = "Microsoft.ApiManagement/service"; ApiVersion = "2022-08-01"; Suffix = "api-management" },
        @{ Type = "Microsoft.AppConfiguration/configurationStores"; ApiVersion = "2023-03-01"; Suffix = "app-configuration" },
        @{ Type = "Microsoft.Batch/batchAccounts"; ApiVersion = "2023-05-01"; Suffix = "batch-accounts" },
        @{ Type = "Microsoft.CognitiveServices/accounts"; ApiVersion = "2023-05-01"; Suffix = "cognitive-services" },
        @{ Type = "Microsoft.MachineLearningServices/workspaces"; ApiVersion = "2023-04-01"; Suffix = "machine-learning" },
        @{ Type = "Microsoft.LoadTestService/loadTests"; ApiVersion = "2022-12-01"; Suffix = "load-testing" }
    )
    foreach ($surface in $secretSurfaceTypes) {
        $encodedType = [uri]::EscapeDataString("resourceType eq '$($surface.Type)'")
        $resources = Invoke-AzRestCollectionSafe -Name "$($surface.Type) resources" -Uri "https://management.azure.com/subscriptions/$sid/resources?`$filter=$encodedType&api-version=2021-04-01"
        foreach ($resource in $resources) {
            $rg = Get-ResourceGroupFromId -ResourceId $resource.id
            $resourceName = Get-ResourceNameFromId -ResourceId $resource.id
            $extractedSecrets = $null

            if ($IncludeSecretValues) {
                switch ($surface.Suffix) {
                    "cosmos-db" {
                        $extractedSecrets = [pscustomobject]@{
                            keys = Invoke-AzRestJsonSafe -Name "Cosmos DB keys for $resourceName" -Method "post" -Uri "$($resource.id)/listKeys?api-version=2023-04-15"
                            readOnlyKeys = Invoke-AzRestJsonSafe -Name "Cosmos DB read-only keys for $resourceName" -Method "post" -Uri "$($resource.id)/readonlykeys?api-version=2023-04-15"
                            connectionStrings = Invoke-AzRestJsonSafe -Name "Cosmos DB connection strings for $resourceName" -Method "post" -Uri "$($resource.id)/listConnectionStrings?api-version=2023-04-15"
                        }
                    }
                    "service-bus" {
                        $rules = Invoke-AzRestCollectionSafe -Name "Service Bus namespace authorization rules for $resourceName" -Uri "$($resource.id)/authorizationRules?api-version=2022-10-01-preview"
                        $ruleKeys = @()
                        foreach ($rule in $rules) {
                            $ruleKeys += [pscustomobject]@{
                                rule = $rule
                                keys = Invoke-AzRestJsonSafe -Name "Service Bus keys for $resourceName/$($rule.name)" -Method "post" -Uri "$($rule.id)/listKeys?api-version=2022-10-01-preview"
                            }
                        }

                        $queues = Invoke-AzRestCollectionSafe -Name "Service Bus queues for $resourceName" -Uri "$($resource.id)/queues?api-version=2022-10-01-preview"
                        $queueRuleKeys = @()
                        foreach ($queue in $queues) {
                            $queueRules = Invoke-AzRestCollectionSafe -Name "Service Bus queue authorization rules for $resourceName/$($queue.name)" -Uri "$($queue.id)/authorizationRules?api-version=2022-10-01-preview"
                            foreach ($queueRule in $queueRules) {
                                $queueRuleKeys += [pscustomobject]@{
                                    queue = $queue
                                    rule = $queueRule
                                    keys = Invoke-AzRestJsonSafe -Name "Service Bus queue keys for $resourceName/$($queue.name)/$($queueRule.name)" -Method "post" -Uri "$($queueRule.id)/listKeys?api-version=2022-10-01-preview"
                                }
                            }
                        }

                        $topics = Invoke-AzRestCollectionSafe -Name "Service Bus topics for $resourceName" -Uri "$($resource.id)/topics?api-version=2022-10-01-preview"
                        $topicRuleKeys = @()
                        foreach ($topic in $topics) {
                            $topicRules = Invoke-AzRestCollectionSafe -Name "Service Bus topic authorization rules for $resourceName/$($topic.name)" -Uri "$($topic.id)/authorizationRules?api-version=2022-10-01-preview"
                            foreach ($topicRule in $topicRules) {
                                $topicRuleKeys += [pscustomobject]@{
                                    topic = $topic
                                    rule = $topicRule
                                    keys = Invoke-AzRestJsonSafe -Name "Service Bus topic keys for $resourceName/$($topic.name)/$($topicRule.name)" -Method "post" -Uri "$($topicRule.id)/listKeys?api-version=2022-10-01-preview"
                                }
                            }
                        }

                        $extractedSecrets = [pscustomobject]@{
                            namespaceRuleKeys = $ruleKeys
                            queueRuleKeys = $queueRuleKeys
                            topicRuleKeys = $topicRuleKeys
                        }
                    }
                    "api-management" {
                        $subscriptionsList = Invoke-AzRestCollectionSafe -Name "API Management subscriptions for $resourceName" -Uri "$($resource.id)/subscriptions?api-version=2022-08-01"
                        $subscriptionSecrets = @()
                        foreach ($apiSubscription in $subscriptionsList) {
                            $subscriptionSecrets += [pscustomobject]@{
                                subscription = $apiSubscription
                                secrets = Invoke-AzRestJsonSafe -Name "API Management subscription secrets for $resourceName/$($apiSubscription.name)" -Method "post" -Uri "$($apiSubscription.id)/listSecrets?api-version=2022-08-01"
                            }
                        }

                        $namedValues = Invoke-AzRestCollectionSafe -Name "API Management named values for $resourceName" -Uri "$($resource.id)/namedValues?api-version=2022-08-01"
                        $namedValueSecrets = @()
                        foreach ($namedValue in $namedValues) {
                            if ($namedValue.properties.secret -eq $true) {
                                $namedValueSecrets += [pscustomobject]@{
                                    namedValue = $namedValue
                                    value = Invoke-AzRestJsonSafe -Name "API Management named value secret for $resourceName/$($namedValue.name)" -Method "post" -Uri "$($namedValue.id)/listValue?api-version=2022-08-01"
                                }
                            }
                        }

                        $extractedSecrets = [pscustomobject]@{
                            subscriptionSecrets = $subscriptionSecrets
                            namedValueSecrets = $namedValueSecrets
                        }
                    }
                    "app-configuration" {
                        $accessKeys = Invoke-AzRestJsonSafe -Name "App Configuration keys for $resourceName" -Method "post" -Uri "$($resource.id)/listKeys?api-version=2023-03-01"
                        $keyValues = @()
                        foreach ($accessKey in @($accessKeys.value)) {
                            if ($accessKey.readOnly -eq $true -or @($accessKeys.value).Count -eq 1) {
                                $keyValues = Invoke-AppConfigurationCollectionSafe -StoreName $resourceName -Endpoint $resource.properties.endpoint -AccessKey $accessKey
                                break
                            }
                        }
                        if (@($keyValues).Count -eq 0 -and @($accessKeys.value).Count -gt 0) {
                            $keyValues = Invoke-AppConfigurationCollectionSafe -StoreName $resourceName -Endpoint $resource.properties.endpoint -AccessKey @($accessKeys.value)[0]
                        }

                        $extractedSecrets = [pscustomobject]@{
                            accessKeys = $accessKeys
                            keyValues = $keyValues
                        }
                    }
                    "batch-accounts" {
                        $batchKeys = Invoke-AzRestJsonSafe -Name "Batch account keys for $resourceName" -Method "post" -Uri "$($resource.id)/listKeys?api-version=2023-05-01"
                        $applications = Invoke-AzRestCollectionSafe -Name "Batch applications for $resourceName" -Uri "$($resource.id)/applications?api-version=2023-05-01"
                        $batchData = $null
                        $batchTokenResponse = Invoke-AzCliJsonSafe -Name "Batch data plane token for $resourceName" -Arguments @("account", "get-access-token", "--resource", "https://batch.core.windows.net/", "--only-show-errors")
                        if ($null -ne $batchTokenResponse -and -not [string]::IsNullOrWhiteSpace($batchTokenResponse.accessToken) -and -not [string]::IsNullOrWhiteSpace($resource.properties.accountEndpoint)) {
                            $batchEndpoint = $resource.properties.accountEndpoint
                            if ($batchEndpoint -notmatch '^https?://') {
                                $batchEndpoint = "https://$batchEndpoint"
                            }
                            $batchEndpoint = $batchEndpoint.TrimEnd([char]"/")
                            $batchApiVersion = "2022-10-01.16.0"

                            $pools = Invoke-BearerRestCollectionSafe -Name "Batch pools for $resourceName" -Uri "$batchEndpoint/pools?api-version=$batchApiVersion&maxresults=1000&paginationeffort=1" -AccessToken $batchTokenResponse.accessToken
                            $jobs = Invoke-BearerRestCollectionSafe -Name "Batch jobs for $resourceName" -Uri "$batchEndpoint/jobs?api-version=$batchApiVersion&maxresults=1000&paginationeffort=1" -AccessToken $batchTokenResponse.accessToken
                            $jobTasks = @()
                            foreach ($job in $jobs) {
                                $tasks = Invoke-BearerRestCollectionSafe -Name "Batch tasks for $resourceName/$($job.id)" -Uri "$($job.url)/tasks?api-version=$batchApiVersion&maxresults=1000&paginationeffort=1" -AccessToken $batchTokenResponse.accessToken
                                $jobTasks += [pscustomobject]@{
                                    job = $job
                                    tasks = $tasks
                                }
                            }

                            $batchData = [pscustomobject]@{
                                endpoint = $batchEndpoint
                                pools = $pools
                                jobs = $jobs
                                jobTasks = $jobTasks
                            }
                        }

                        $extractedSecrets = [pscustomobject]@{
                            keys = $batchKeys
                            applications = $applications
                            batchData = $batchData
                        }
                    }
                    "cognitive-services" {
                        $extractedSecrets = [pscustomobject]@{
                            keys = Invoke-AzRestJsonSafe -Name "Cognitive Services keys for $resourceName" -Method "post" -Uri "$($resource.id)/listKeys?api-version=2023-05-01"
                        }
                    }
                    "machine-learning" {
                        $connections = Invoke-AzRestCollectionSafe -Name "Machine Learning connections for $resourceName" -Uri "$($resource.id)/connections?api-version=2023-08-01-preview"
                        $connectionSecrets = @()
                        foreach ($connection in $connections) {
                            $connectionSecrets += [pscustomobject]@{
                                connection = $connection
                                secrets = Invoke-AzRestJsonSafe -Name "Machine Learning connection secrets for $resourceName/$($connection.name)" -Method "post" -Uri "$($connection.id)/listsecrets?api-version=2023-08-01-preview"
                            }
                        }

                        $datastores = Invoke-AzRestCollectionSafe -Name "Machine Learning datastores for $resourceName" -Uri "$($resource.id)/datastores?api-version=2023-08-01-preview"
                        $extractedSecrets = [pscustomobject]@{
                            connections = $connectionSecrets
                            datastores = $datastores
                        }
                    }
                    "load-testing" {
                        $extractedSecrets = [pscustomobject]@{
                            dataPlaneUri = $resource.properties.dataPlaneURI
                            identity = $resource.identity
                        }
                    }
                }
            }

            $otherSecretSurfaceRecords.Add((Add-Record -Kind "MBSecretSurface" -Data ([pscustomobject]@{
                subscriptionId = $sid
                id = $resource.id
                name = $resource.name
                type = $resource.type
                location = $resource.location
                identity = $resource.identity
                properties = $resource.properties
                microBurstPrimitive = $surface.Suffix
                extractedSecrets = ConvertTo-SafeValue -Value $extractedSecrets
            })))
        }
    }
    Write-StepOutput -Suffix "secret-surfaces" -StepRecords $otherSecretSurfaceRecords
}

Write-AzureHoundStatus -Stage "MB" -Message "Finished MicroBurst-inspired checks with $($records.Count) record(s)"
Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
