param(
    [Parameter(Mandatory = $true)]
    [ValidateSet(
        "enum-cas",
        "enum-templates",
        "enum-pkiobjects",
        "request",
        "request-agent",
        "request-download",
        "request-renew",
        "forge",
        "manage-ca",
        "manage-template",
        "manage-self"
    )]
    [string]$Command,

    [hashtable]$Arguments = @{}
)

$scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "$Command.ps1"
if (-not (Test-Path -Path $scriptPath)) {
    throw "Command script not found: $scriptPath"
}

& $scriptPath @Arguments
