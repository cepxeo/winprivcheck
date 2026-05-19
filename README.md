## Read LAPS pass

.\Get-LapsPasswordForComputer.ps1 -ComputerName WS01
.\Get-LapsPasswordForComputer.ps1 -ComputerName WS01 -DomainController dc01.contoso.local

$Cred = Get-Credential
.\Get-LapsPasswordForComputer.ps1 -ComputerName WS01 -Credential $Cred

## Change domain user pass

.\Set-DomainUserPass.ps1 -Identity jsmith

$Cred = Get-Credential
.\Set-DomainUserPass.ps1 -Identity jsmith -Credential $Cred

$Cred = Get-Credential
.\Set-DomainUserPass.ps1 -Identity jsmith -DomainController dc01.contoso.local -Credential $Cred

$NewPassword = Read-Host "New password" -AsSecureString
.\Set-DomainUserPass.ps1 -Identity jsmith -NewPassword $NewPassword -Credential $Cred


# PrivCheck Techniques

This directory contains the split PrivCheck technique scripts. Each numbered
`.ps1` file runs one focused Windows privilege-escalation, hardening, inventory,
or credential-artifact check and loads shared helpers from `common.ps1`.

`common.ps1` is support code and is not intended to be run directly.

## Arguments

Every numbered script accepts the same switches:

| Argument | Description |
| --- | --- |
| `-TimeStamp` | Prints elapsed runtime before each section header. Useful when running several scripts in sequence. |
| `-FullCheck` | Enables broader checks where supported. In the password search scripts this adds extra token/API-key regexes. |
| `-Excel` | Enables Excel workbook content searching for `62-file-password-search.ps1` when Microsoft Excel COM automation is available. |

Scripts may ignore a switch if that technique has no matching expanded behavior.
Some checks need administrative rights, domain context, installed Windows
features, or access to user profiles to return complete results.

## Execution Examples

Run one technique:

```powershell
.\techniques\01-system-information.ps1
```

Run with timestamps:

```powershell
.\techniques\39-active-directory-identity-checks.ps1 -TimeStamp
```

Run a full password search, including Excel workbook content when supported:

```powershell
.\techniques\62-file-password-search.ps1 -FullCheck -Excel
```

Run a registry secret search with the expanded regex set:

```powershell
.\techniques\63-registry-password-search.ps1 -FullCheck
```

Run all numbered techniques from the repository root:

```powershell
Get-ChildItem .\techniques -Filter '*.ps1' |
  Where-Object { $_.Name -match '^\d{2}-' } |
  Sort-Object Name |
  ForEach-Object { & $_.FullName -TimeStamp }
```

If local execution policy blocks unsigned scripts, use a process-scoped bypass
for the current PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Technique Catalog

| Script | Technique | Brief explanation |
| --- | --- | --- |
| `01-system-information.ps1` | System information | Prints OS, host, and platform details useful for deciding which checks apply. |
| `02-windows-hotfixes.ps1` | Windows hotfixes | Lists installed hotfixes and patch identifiers. |
| `03-printnightmare-pointandprint-policy.ps1` | PrintNightmare policy | Checks Point and Print registry policy values related to printer-driver abuse risk. |
| `04-windows-update-history.ps1` | Update history | Reads Windows Update history and extracts KB identifiers where possible. |
| `05-drive-info.ps1` | Drive inventory | Lists local fixed drives, size, and free-space information. |
| `06-antivirus-detection.ps1` | Antivirus and Defender exclusions | Reports registered antivirus products and Windows Defender exclusion paths/settings. |
| `07-net-accounts.ps1` | Account policy | Runs account-policy enumeration such as password and lockout policy details. |
| `08-audit-log-settings.ps1` | Audit policy | Shows audit policy and event log configuration that affects evidence collection. |
| `09-windows-event-forwarding.ps1` | Event forwarding | Checks registry settings for Windows Event Forwarding subscriptions/configuration. |
| `10-laps-check.ps1` | LAPS | Checks for Local Administrator Password Solution configuration and related indicators. |
| `11-wdigest-check.ps1` | WDigest | Checks whether WDigest plaintext credential caching is enabled. |
| `12-lsa-protection.ps1` | LSA protection | Checks RunAsPPL/LSA protection settings. |
| `13-credential-guard.ps1` | Credential Guard | Checks Credential Guard and virtualization-based security indicators. |
| `14-winlogon-credentials.ps1` | Winlogon credentials | Looks for AutoAdminLogon and related Winlogon credential registry values. |
| `15-rdcman-settings.ps1` | RDCMan settings | Searches for Remote Desktop Connection Manager settings and credential artifacts. |
| `16-rdp-saved-connections.ps1` | RDP saved connections | Enumerates saved RDP connection history under user registry hives. |
| `17-putty-stored-credentials.ps1` | PuTTY sessions | Checks saved PuTTY session registry entries for usernames, hosts, and proxy credentials. |
| `18-ssh-key-checks.ps1` | SSH keys | Looks for SSH keys and related configuration files in user profile locations. |
| `19-vnc-snmp-passwords.ps1` | VNC/SNMP passwords | Checks common VNC and SNMP registry/configuration locations for stored secrets. |
| `20-uac-settings.ps1` | UAC settings | Reports User Account Control policy values that influence elevation behavior. |
| `21-recently-run-commands.ps1` | Recent commands | Enumerates recent command and RunMRU style artifacts. |
| `22-always-install-elevated.ps1` | AlwaysInstallElevated | Checks machine and user MSI policy values for unsafe elevated installer behavior. |
| `23-powershell-info-and-logging.ps1` | PowerShell info/logging bundle | Summarizes PowerShell version and logging-related settings. |
| `24-wsus-settings.ps1` | WSUS settings | Reports Windows Update/WSUS policy configuration. |
| `25-internet-settings.ps1` | Internet settings | Dumps relevant HKCU/HKLM Internet Settings values such as proxy configuration. |
| `26-running-process-acls.ps1` | Running process ACLs | Checks file ACLs for running process binaries for writable paths. |
| `27-system-processes.ps1` | SYSTEM processes | Lists processes running as SYSTEM or other high-value contexts. |
| `28-service-binary-acls.ps1` | Service binary ACLs | Checks service executable paths for writable files or parent directories. |
| `29-unquoted-service-paths.ps1` | Unquoted service paths | Finds services whose executable path is unquoted and contains spaces. |
| `30-service-registry-acls.ps1` | Service registry ACLs | Checks service registry keys for writable permissions. |
| `31-scheduled-tasks.ps1` | Scheduled tasks | Enumerates scheduled tasks, commands, users, and task paths. |
| `32-startup-folder-acls.ps1` | Startup folder ACLs | Checks startup folders for writable permissions. |
| `33-startup-registry-acls.ps1` | Startup registry ACLs | Checks common Run/RunOnce registry locations for writable permissions. |
| `34-installed-applications.ps1` | Installed applications | Lists installed x64 and x86 applications from uninstall registry keys. |
| `35-wsl-bash-check.ps1` | WSL/Bash | Checks for Windows Subsystem for Linux/Bash components. |
| `36-sccm-client.ps1` | SCCM client | Checks for Microsoft Configuration Manager client artifacts. |
| `37-hosts-file.ps1` | Hosts file | Prints the Windows hosts file for name-resolution overrides. |
| `38-ipconfig-dns-netstat.ps1` | Network bundle | Runs combined IP configuration, DNS cache, and listening-port checks. |
| `39-active-directory-identity-checks.ps1` | Active Directory identity checks | Checks AD/domain items such as NTLM policy, time skew, DNS ACLs, SPN targets, gMSA readers, and AD CS Schannel hints. |
| `40-arp-routes-adapters.ps1` | Network table bundle | Runs combined ARP table, route, and network adapter checks. |
| `41-wifi-passwords.ps1` | Wi-Fi passwords | Attempts to enumerate saved Wi-Fi profiles and cleartext keys where permitted. |
| `42-firewall-rule-command.ps1` | Firewall rule commands | Lists firewall rules and associated command/program paths. |
| `43-smb-shares.ps1` | SMB shares | Lists local SMB shares and checks share paths for risky writable ACLs. |
| `44-local-groups-and-members.ps1` | Local groups | Lists local groups and their members. |
| `45-user-directory-access.ps1` | User directory access | Checks whether other user profile directories are accessible. |
| `46-whoami-token-info.ps1` | Token information | Runs identity, group, and privilege enumeration for the current token. |
| `47-cloud-credentials.ps1` | Cloud credentials | Searches user profile locations for common cloud CLI credential/configuration files. |
| `48-appcmd-check.ps1` | IIS appcmd | Checks IIS AppCmd locations and related configuration for recoverable credentials. |
| `49-openvpn-credentials.ps1` | OpenVPN credentials | Searches common OpenVPN configuration paths for credential references. |
| `50-powershell-history.ps1` | PowerShell history | Searches PSReadLine history files for password-like content. |
| `51-environment-variables.ps1` | Environment variables | Dumps environment variables that may expose paths, tokens, or configuration. |
| `52-sticky-notes.ps1` | Sticky Notes | Checks Sticky Notes storage locations for note databases or cached text. |
| `53-cached-credentials.ps1` | Cached credentials | Runs Windows cached credential enumeration commands where available. |
| `54-dpapi-masterkeys.ps1` | DPAPI masterkeys | Lists DPAPI masterkey files under user profile locations. |
| `55-dpapi-credentials.ps1` | DPAPI credential files | Lists DPAPI credential blobs under user profile locations. |
| `56-sessions-and-tickets.ps1` | Session/ticket bundle | Runs logged-on user, remote session, and Kerberos ticket checks. |
| `57-clipboard-text.ps1` | Clipboard text | Prints current clipboard text when accessible. |
| `58-unattended-files.ps1` | Unattended files | Searches common Windows setup/unattend file paths for deployment secrets. |
| `59-sam-system-backups.ps1` | SAM/SYSTEM backups | Checks common backup locations for SAM, SYSTEM, and related registry hive copies. |
| `60-group-policy-passwords.ps1` | Group Policy passwords | Searches SYSVOL/GPP policy files for legacy stored credentials. |
| `61-recycle-bin-tip.ps1` | Recycle Bin reminder | Prints a reminder to inspect recycle bins for deleted sensitive files. |
| `62-file-password-search.ps1` | File password search | Searches common file locations for usernames, passwords, secrets, keys, and optional Excel content. |
| `63-registry-password-search.ps1` | Registry password search | Searches registry content for password-like values and, with `-FullCheck`, broader token patterns. |
| `64-powershell-version.ps1` | PowerShell version | Prints PowerShell version and host information. |
| `65-powershell-transcription-log.ps1` | PowerShell transcription logging | Checks transcription logging registry settings. |
| `66-powershell-module-log.ps1` | PowerShell module logging | Checks module logging registry settings. |
| `67-powershell-scriptblock-log.ps1` | PowerShell script block logging | Checks script block logging registry settings. |
| `68-ipconfig-all.ps1` | IP configuration | Runs `ipconfig /all` for network adapter and DNS details. |
| `69-dns-cache.ps1` | DNS cache | Prints cached DNS entries. |
| `70-listening-ports.ps1` | Listening ports | Lists listening TCP/UDP ports and owning processes where available. |
| `71-arp-table.ps1` | ARP table | Prints ARP neighbor entries. |
| `72-routes.ps1` | Routes | Prints route table information. |
| `73-network-adapters.ps1` | Network adapters | Lists network adapter details. |
| `74-current-logged-on-users.ps1` | Logged-on users | Lists current interactive/logged-on user sessions. |
| `75-remote-sessions.ps1` | Remote sessions | Lists remote desktop/session information where commands are available. |
| `76-kerberos-tickets.ps1` | Kerberos tickets | Lists current Kerberos tickets. |

