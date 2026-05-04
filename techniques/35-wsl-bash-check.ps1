[CmdletBinding()]
param([switch]$TimeStamp, [switch]$FullCheck, [switch]$Excel)
. "$PSScriptRoot\common.ps1" -TimeStamp:$TimeStamp -FullCheck:$FullCheck -Excel:$Excel

Write-PrivCheckSection 'WSL / BASH CHECK'
Get-ChildItem C:\Windows\WinSxS\ -Filter 'amd64_microsoft-windows-lxss-bash*' -ErrorAction SilentlyContinue |
  ForEach-Object { Get-ChildItem $_.FullName -Recurse -Filter '*bash.exe*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName }
foreach ($name in 'bash.exe', 'wsl.exe') {
  Get-ChildItem C:\Windows\System32\ -Filter $name -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
}
