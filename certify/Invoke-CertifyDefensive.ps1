param(
    [string]$Command,
    [hashtable]$Arguments = @{}
)

$allowedCommands = @(
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
)

if ([string]::IsNullOrWhiteSpace($Command)) {
    $Command = [Environment]::GetEnvironmentVariable('CERTIFY_COMMAND')
}

if ([string]::IsNullOrWhiteSpace($Command)) {
    throw "Command is required. Pass -Command or set environment variable CERTIFY_COMMAND."
}

if ($allowedCommands -notcontains $Command) {
    throw "Unknown command '$Command'. Allowed: $($allowedCommands -join ', ')"
}

$scriptPath = Join-Path -Path $PSScriptRoot -ChildPath "$Command.ps1"
if (-not (Test-Path -Path $scriptPath)) {
    throw "Command script not found: $scriptPath"
}

& $scriptPath @Arguments
