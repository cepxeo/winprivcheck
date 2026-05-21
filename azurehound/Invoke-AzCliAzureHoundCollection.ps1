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

        $args = @("-OutputPath", $adOut)
        if ($SkipRelationships) { $args += "-SkipRelationships" }
        if ($ContinueOnError) { $args += "-ContinueOnError" }
        & "$PSScriptRoot/Collect-AzureAD.ps1" @args

        $doc = Get-Content -Path $adOut -Raw | ConvertFrom-Json
        foreach ($record in @($doc.data)) {
            $records.Add($record)
        }
    }

    if ($Scope -in @("All", "AzureRM")) {
        $rmOut = Join-Path ([System.IO.Path]::GetTempPath()) ("azurehound-rm-{0}.json" -f ([guid]::NewGuid()))
        $tempFiles.Add($rmOut)

        $args = @("-OutputPath", $rmOut)
        if (@($SubscriptionId).Count -gt 0) {
            $args += "-SubscriptionId"
            $args += $SubscriptionId
        }
        if (@($ManagementGroupId).Count -gt 0) {
            $args += "-ManagementGroupId"
            $args += $ManagementGroupId
        }
        if ($SkipRelationships) { $args += "-SkipRelationships" }
        if ($ContinueOnError) { $args += "-ContinueOnError" }
        & "$PSScriptRoot/Collect-AzureRM.ps1" @args

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
