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

Assert-AzCliAvailable

$records = [System.Collections.Generic.List[object]]::new()
$tempFiles = [System.Collections.Generic.List[string]]::new()

try {
    if ($Scope -in @("All", "AzureAD")) {
        $adOut = Join-Path ([System.IO.Path]::GetTempPath()) ("azurehound-ad-{0}.json" -f ([guid]::NewGuid()))
        $tempFiles.Add($adOut)

        $adParams = @{
            OutputPath = $adOut
        }
        if ($SkipRelationships) { $adParams.SkipRelationships = $true }
        if ($ContinueOnError) { $adParams.ContinueOnError = $true }
        & "$PSScriptRoot/Collect-AzureAD.ps1" @adParams

        $doc = Get-Content -Path $adOut -Raw | ConvertFrom-Json
        foreach ($record in @($doc.data)) {
            $records.Add($record)
        }
    }

    if ($Scope -in @("All", "AzureRM")) {
        $rmOut = Join-Path ([System.IO.Path]::GetTempPath()) ("azurehound-rm-{0}.json" -f ([guid]::NewGuid()))
        $tempFiles.Add($rmOut)

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

        $doc = Get-Content -Path $rmOut -Raw | ConvertFrom-Json
        foreach ($record in @($doc.data)) {
            $records.Add($record)
        }
    }

    Write-AzureHoundOutput -Records $records -OutputPath $OutputPath
}
finally {
    foreach ($file in $tempFiles) {
        if (Test-Path $file) {
            Remove-Item -Path $file -Force
        }
    }
}
