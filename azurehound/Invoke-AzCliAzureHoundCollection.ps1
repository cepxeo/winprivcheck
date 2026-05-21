[CmdletBinding()]
param(
    [ValidateSet("All", "AzureAD", "AzureRM")]
    [string] $Scope = "All",

    [string] $OutputPath = "azurehound-azcli.json",

    [string[]] $SubscriptionId,
    [string[]] $ManagementGroupId,
    [switch] $SkipRelationships,
    [switch] $ContinueOnError
)

. "$PSScriptRoot/AzCliAzureHound.Common.ps1"

Write-AzureHoundStatus -Stage "START" -Message "Starting AzureHound Azure CLI collection with scope $Scope"
Write-AzureHoundStatus -Stage "START" -Message "Requested output path: $OutputPath"
Assert-AzCliAvailable

$records = [System.Collections.Generic.List[object]]::new()
$tempFiles = [System.Collections.Generic.List[string]]::new()

try {
    if ($Scope -in @("All", "AzureAD")) {
        Write-AzureHoundStatus -Stage "AZAD" -Message "Starting Entra ID collection"
        $adOut = Join-Path ([System.IO.Path]::GetTempPath()) ("azurehound-ad-{0}.json" -f ([guid]::NewGuid()))
        $tempFiles.Add($adOut)
        Write-AzureHoundStatus -Stage "AZAD" -Message "Using temporary Entra ID output $adOut"

        $adParams = @{
            OutputPath = $adOut
        }
        if ($SkipRelationships) { $adParams.SkipRelationships = $true }
        if ($ContinueOnError) { $adParams.ContinueOnError = $true }
        & "$PSScriptRoot/Collect-AzureAD.ps1" @adParams

        Write-AzureHoundStatus -Stage "AZAD" -Message "Merging Entra ID records from $adOut"
        $doc = Get-Content -Path $adOut -Raw | ConvertFrom-Json
        foreach ($record in @($doc.data)) {
            $records.Add($record)
        }
        Write-AzureHoundStatus -Stage "AZAD" -Message "Merged $(@($doc.data).Count) Entra ID record(s)"
    }

    if ($Scope -in @("All", "AzureRM")) {
        Write-AzureHoundStatus -Stage "AZRM" -Message "Starting Azure Resource Manager collection"
        $rmOut = Join-Path ([System.IO.Path]::GetTempPath()) ("azurehound-rm-{0}.json" -f ([guid]::NewGuid()))
        $tempFiles.Add($rmOut)
        Write-AzureHoundStatus -Stage "AZRM" -Message "Using temporary Azure RM output $rmOut"

        $rmParams = @{
            OutputPath = $rmOut
        }
        if (@($SubscriptionId).Count -gt 0) {
            $rmParams.SubscriptionId = $SubscriptionId
        }
        if (@($ManagementGroupId).Count -gt 0) {
            $rmParams.ManagementGroupId = $ManagementGroupId
        }
        if ($SkipRelationships) { $rmParams.SkipRelationships = $true }
        if ($ContinueOnError) { $rmParams.ContinueOnError = $true }
        & "$PSScriptRoot/Collect-AzureRM.ps1" @rmParams

        Write-AzureHoundStatus -Stage "AZRM" -Message "Merging Azure RM records from $rmOut"
        $doc = Get-Content -Path $rmOut -Raw | ConvertFrom-Json
        foreach ($record in @($doc.data)) {
            $records.Add($record)
        }
        Write-AzureHoundStatus -Stage "AZRM" -Message "Merged $(@($doc.data).Count) Azure RM record(s)"
    }

    Write-AzureHoundStatus -Stage "DONE" -Message "Writing combined output with $($records.Count) record(s)"
    Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
}
finally {
    foreach ($file in $tempFiles) {
        if (Test-Path $file) {
            Write-AzureHoundStatus -Stage "CLEANUP" -Message "Removing temporary file $file"
            Remove-Item -Path $file -Force
        }
    }
}
