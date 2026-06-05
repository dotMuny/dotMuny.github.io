---
layout: post
title: OverTheWire - Bandit Complete Walkthrough
description: "Complete walkthrough of the OverTheWire Bandit wargame from level 0 to 34. Covers SSH, Linux file enumeration, special filenames, hidden files, grep, base64, ROT13, hexdump decompression, SSH key authentication, netcat, OpenSSL TLS, nmap port scanning, SUID binaries, cron jobs, restricted shell escapes, and Git security."
subtitle: A complete walkthrough of the OverTheWire Bandit wargame.
date: 2026-06-05 00:00:00
background: ""
tags: [posts]
category: cybersecurity
---
![](/img/blog_img/OverTheWireBandit_img/img1.png)


# OverTheWire Bandit complete walkthrough

## Introduction

Bandit is one of the most beginner-friendly wargames from OverTheWire. It is designed to teach core Linux and command-line concepts through a sequence of practical challenges.

Each level provides the password for the next one. The goal is to enumerate the system, understand the challenge conditions, retrieve the password, and use it to SSH into the next user.

This writeup documents the process from Bandit Level 0 to Bandit Level 34.

> Passwords are intentionally redacted and replaced with `<REDACTED>`.

---

## Target Information

|Item|Value|
|---|---|
|Wargame|Bandit|
|Platform|OverTheWire|
|Host|`bandit.labs.overthewire.org`|
|SSH Port|`2220`|
|Initial User|`bandit0`|
|Initial Password|`bandit0`|

---

## General SSH Syntax

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

For later levels:

```bash
ssh bandit<N>@bandit.labs.overthewire.org -p 2220
```

Example:

```bash
ssh bandit10@bandit.labs.overthewire.org -p 2220
```

---

## Progress Overview

|Level|Main Concept|
|---|---|
|Bandit 0 → 1|SSH and basic file reading|
|Bandit 1 → 2|Special filenames|
|Bandit 2 → 3|Spaces in filenames|
|Bandit 3 → 4|Hidden files|
|Bandit 4 → 5|File type detection|
|Bandit 5 → 6|Finding files by properties|
|Bandit 6 → 7|Finding files by owner, group and size|
|Bandit 7 → 8|Searching inside files|
|Bandit 8 → 9|Finding unique lines|
|Bandit 9 → 10|Extracting readable strings|
|Bandit 10 → 11|Base64 decoding|
|Bandit 11 → 12|ROT13 decoding|
|Bandit 12 → 13|Hexdump reversing and decompression|
|Bandit 13 → 14|SSH private key authentication|
|Bandit 14 → 15|TCP communication with Netcat|
|Bandit 15 → 16|TLS communication with OpenSSL|
|Bandit 16 → 17|Port scanning and private key extraction|
|Bandit 17 → 18|File comparison|
|Bandit 18 → 19|Remote command execution over SSH|
|Bandit 19 → 20|SUID binary usage|
|Bandit 20 → 21|Local socket interaction|
|Bandit 21 → 22|Cron job enumeration|
|Bandit 22 → 23|Bash script analysis|
|Bandit 23 → 24|Cron-based script execution|
|Bandit 24 → 25|Brute forcing a PIN|
|Bandit 25 → 26|Restricted shell behavior|
|Bandit 26 → 27|Escaping restricted environments|
|Bandit 27 → 28|Git over SSH|
|Bandit 28 → 29|Git history|
|Bandit 29 → 30|Git branches|
|Bandit 30 → 31|Git tags|
|Bandit 31 → 32|Git push and ignored files|
|Bandit 32 → 33|Escaping an uppercase shell|
|Bandit 33 → 34|Final message|

---

# Bandit Level 0 → Level 1

## Objective

Log into the Bandit server using SSH and retrieve the password for `bandit1`.

## Credentials

```text
Username: bandit0
Password: bandit0
Host: bandit.labs.overthewire.org
Port: 2220
```

## Commands

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

Once logged in:

```bash
ls -la
cat readme
```

## Result

```text
Congratulations on your first steps into the bandit game!!
Please make sure you have read the rules at https://overthewire.org/rules/
If you are following a course, workshop, walkthrough or other educational activity,
please inform the instructor about the rules as well and encourage them to
contribute to the OverTheWire community so we can keep these games free!

The password you are looking for is: <REDACTED>

```

## Explanation

The first level introduces SSH access and basic file reading. The password for the next level is stored inside a file named `readme` in the home directory.

## Key Takeaways

- SSH can connect to a remote system using a custom port.
- `ls -la` lists files, including hidden files and permissions.
- `cat` displays the contents of a file.

---

# Bandit Level 1 → Level 2

## Objective

Read the password stored in a file named `-`.

## Commands

```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
ls -la
cat ./-
```

## Result

```text
<REDACTED>
```

## Explanation

A filename such as `-` can be interpreted by some commands as an option or as standard input. By using `./-`, we explicitly tell the shell to read the file named `-` from the current directory.

## Key Takeaways

- Special filenames can require explicit paths.
- `./` refers to the current directory.
- Not all filenames are safe to use directly without context.

---

# Bandit Level 2 → Level 3

## Objective

Read a file whose name contains spaces.

## Commands

```bash
ssh bandit2@bandit.labs.overthewire.org -p 2220
ls -la
cat ./"--spaces in this filename--"
```

Alternative:

```bash
cat ./--spaces\ in\ this\ filename--
```

## Result

```text
<REDACTED>
```

## Explanation

Spaces separate command arguments in the shell. If a filename contains spaces, it must be wrapped in quotes or the spaces must be escaped using backslashes.

## Key Takeaways

- Use quotes around filenames containing spaces.
- Escape special characters with `\`.
- Shell parsing matters when interacting with unusual filenames.

---

# Bandit Level 3 → Level 4

## Objective

Find the password hidden inside a directory.

## Commands

```bash
ssh bandit3@bandit.labs.overthewire.org -p 2220
ls -la
cd inhere
ls -la

cat ...Hiding-From-You
```

## Result

```text
<REDACTED>
```

## Explanation

Linux treats files beginning with a dot as hidden files. They are not shown by a normal `ls`, but they appear when using `ls -a`.

## Key Takeaways

- Hidden files begin with `.`.
- `ls -la` is useful for complete directory enumeration.
- Always inspect directories carefully in CTF-style environments.

---

# Bandit Level 4 → Level 5

## Objective

Find the only human-readable file inside the `inhere` directory.

## Commands

```bash
ssh bandit4@bandit.labs.overthewire.org -p 2220
cd inhere
ls -la

file ./*
./-file00: data
./-file01: data
./-file02: data
./-file03: DOS executable (COM), start instruction 0x8c887e10 c3ee96c9
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
```

After identifying the readable file:

```bash
bandit4@bandit:~/inhere$ cat ./-file07
```

## Result

```text
<REDACTED>
```

## Explanation

The directory contains several files, but only one is human-readable. The `file` command identifies the type of each file, making it easy to distinguish ASCII text from binary data.

## Key Takeaways

- `file` identifies file types.
- A file extension is not required for Linux to identify file content.
- Human-readable content can be filtered using file type analysis.

---

# Bandit Level 5 → Level 6

## Objective

Find a file somewhere under the `inhere` directory with the following properties:

```text
Human-readable
1033 bytes in size
Not executable
```

## Commands

```bash
ssh bandit5@bandit.labs.overthewire.org -p 2220
cd inhere
find . -type f -size 1033c ! -executable

./maybehere07/.file2
```

Read the file:

```bash
cat ./maybehere07/.file2
```

## Result

```text
<REDACTED>
```

## Explanation

The `find` command is used to search recursively for files matching specific criteria. In this case, we filter by file type, exact size, and executable permissions.

## Key Takeaways

- `find` is one of the most useful Linux enumeration commands.
- `-type f` restricts results to regular files.
- `-size 1033c` searches for a file exactly 1033 bytes long.
- `! -executable` excludes executable files.

---

# Bandit Level 6 → Level 7

## Objective

Find a file somewhere on the system with these properties:

```text
Owned by user: bandit7
Owned by group: bandit6
Size: 33 bytes
```

## Commands

```bash
ssh bandit6@bandit.labs.overthewire.org -p 2220

find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

Read the discovered file:

```bash
find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null
/var/lib/dpkg/info/bandit7.password

cat /var/lib/dpkg/info/bandit7.password
```

## Result

```text
<REDACTED>
```

## Explanation

The search starts from `/`, which means it traverses the whole filesystem. Many directories are not readable by the current user, so permission errors are expected. Redirecting stderr to `/dev/null` removes those errors from the output.

## Key Takeaways

- `find /` searches from the root of the filesystem.
- `-user`, `-group`, and `-size` can be combined for precise searches.
- `2>/dev/null` suppresses permission-denied errors.

---

# Bandit Level 7 → Level 8

## Objective

Find the password next to the word `millionth` inside `data.txt`.

## Commands

```bash
ssh bandit7@bandit.labs.overthewire.org -p 2220
ls -la
grep "millionth" data.txt
```

## Result

```text
grep "millionth" data.txt
millionth       <REDACTED>
```

## Explanation

The file contains many lines, but only one line contains the marker word `millionth`. `grep` filters the file and prints only the matching line.

## Key Takeaways

- `grep` searches for patterns inside files.
- Keyword-based filtering is essential when handling large text files.

---

# Bandit Level 8 → Level 9

## Objective

Find the only line in `data.txt` that appears once.

## Commands

```bash
ssh bandit8@bandit.labs.overthewire.org -p 2220
sort data.txt | uniq -u
```

## Result

```text
<REDACTED>
```

## Explanation

`uniq` only detects duplicate adjacent lines. Therefore, the file must be sorted first. The `-u` option prints only lines that occur once.

## Key Takeaways

- `sort` organizes lines before duplicate analysis.
- `uniq -u` prints only unique lines.
- Pipes allow chaining commands together.

---

# Bandit Level 9 → Level 10

## Objective

Find the password inside a file containing mostly non-readable data. The password is preceded by several `=` characters.

## Commands

```bash
ssh bandit9@bandit.labs.overthewire.org -p 2220
strings data.txt | grep "==="
```

## Result

```text
bandit9@bandit:~$ strings data.txt | grep "==="
========== the
========== password
========== is
========== <REDACTED>
```

## Explanation

The `strings` command extracts printable character sequences from binary-like files. Piping its output to `grep` filters the result for lines containing `==`.

## Key Takeaways

- `strings` is useful for inspecting binary files.
- Combining `strings` with `grep` is a common triage technique.
- Binary files may still contain useful plaintext strings.

---

# Bandit Level 10 → Level 11

## Objective

Decode a Base64-encoded password.

## Commands

```bash
ssh bandit10@bandit.labs.overthewire.org -p 2220
base64 -d data.txt
```

## Result

```
bandit10@bandit:~$ cat data.txt
VGhlIHBhc3N3b3JkIGlzIGR0UjE3M2...g==
bandit10@bandit:~$ base64 -d data.txt
The password is <REDACTED>
```

## Explanation

Base64 is an encoding format, not encryption. The `-d` option decodes the content.

## Key Takeaways

- Base64 is reversible encoding.
- `base64 -d` decodes Base64 content.
- Encoded data should not be treated as securely encrypted data.

---

# Bandit Level 11 → Level 12

## Objective

Decode a ROT13-transformed password.

## Commands

```bash
ssh bandit11@bandit.labs.overthewire.org -p 2220
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

Alternative:

```bash
tr 'A-Za-z' 'N-ZA-Mn-za-m' < data.txt
```

## Result

```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
The password is <REDACTED>
```

## Explanation

ROT13 shifts each letter by 13 positions in the alphabet. Since the alphabet has 26 letters, applying ROT13 twice returns the original text.

## Key Takeaways

- ROT13 is a simple Caesar-style substitution.
- `tr` can translate character sets.
- Input redirection can replace unnecessary use of `cat`.

---

# Bandit Level 12 → Level 13

## Objective

Recover a password stored in a file that has been hexdumped and compressed multiple times.

## Commands

Create a temporary working directory:

```bash
ssh bandit12@bandit.labs.overthewire.org -p 2220
mkdir /tmp/bandit12_work
cd /tmp/bandit12_work
cp ~/data.txt .
```

Reverse the hexdump:

```bash
xxd -r data.txt data
file data
```

Then identify and decompress each layer based on the output of `file`.

Example workflow:

```bash
file data
mv data data.gz
gzip -d data.gz

file data
mv data data.bz2
bzip2 -d data.bz2

file data
mv data data.tar
tar xf data.tar

file data5.bin
```

Repeat the process until the final file is plain ASCII text:

```bash
cat data8
```

## Result

```text
cat data8
The password is <REDACTED>
```

## Explanation

The original file is a hexdump. First, `xxd -r` is used to reverse it into binary form. After that, `file` is used repeatedly to identify each compression layer. Depending on the detected type, the file is renamed and decompressed using the appropriate tool.

## Key Takeaways

- `xxd -r` reverses a hexdump.
- `file` should be used after every extraction step.
- Compressed files may be nested multiple times.
- Common formats include `gzip`, `bzip2`, and `tar`.

---

# Bandit Level 13 → Level 14

## Objective

Use a private SSH key to log in as `bandit14`.

## Commands

```bash
ssh bandit13@bandit.labs.overthewire.org -p 2220
ls -lah
total 28K
drwxr-xr-x   2 root     root     4.0K Apr  3 15:17 .
drwxr-xr-x 150 root     root     4.0K Apr  3 15:20 ..
-rw-r--r--   1 root     root      220 Mar 31  2024 .bash_logout
-rw-r--r--   1 root     root     3.8K Apr  3 15:10 .bashrc
-rw-r-----   1 bandit14 bandit13  467 Apr  3 15:17 HINT
-rw-r--r--   1 root     root      807 Mar 31  2024 .profile
-rw-r-----   1 bandit14 bandit13 1.7K Apr  3 15:17 sshkey.private
```

The home directory contains a private key:

```bash
cat sshkey.private
```

We can save it to our system, `chmod 600` it and then use it to authenticate as `bandit14`:

```bash
ssh -i sshkey.private bandit14@bandit.labs.overthewire.org -p 2220
```

After logging in as `bandit14`, read the current password:

```bash
cat /etc/bandit_pass/bandit14
```

## Result

```text
<REDACTED>
```

## Explanation

Instead of providing a password directly, this level provides a private SSH key. The key allows authentication as `bandit14`.

## Key Takeaways

- SSH supports key-based authentication.
- `ssh -i <key>` specifies a private key file.
- Password files are stored under `/etc/bandit_pass/`.

---

# Bandit Level 14 → Level 15

## Objective

Submit the current password to a service listening on port `30000` on localhost.

## Commands

```bash
ssh bandit14@bandit.labs.overthewire.org -p 2220
cat /etc/bandit_pass/bandit14
nc localhost 30000
```

Paste the current password into the Netcat session.

Alternative one-liner:

```bash
cat /etc/bandit_pass/bandit14 | nc localhost 30000
```

## Result

```text
Correct!
<REDACTED>
```

## Explanation

The local service checks whether the submitted password is correct. If it is, it returns the password for the next level.

## Key Takeaways

- `nc` can interact with TCP services.
- Localhost services can be tested from the same machine.
- Piping can automate simple client-server interactions.

---

# Bandit Level 15 → Level 16

## Objective

Submit the current password to a service listening on port `30001` using SSL/TLS.

## Commands

```bash
ssh bandit15@bandit.labs.overthewire.org -p 2220
openssl s_client -connect localhost:30001
```

Paste the current password into the TLS session.

Cleaner output:

```bash
openssl s_client -connect localhost:30001 -quiet
```

## Result

```text
openssl s_client -connect localhost:30001 -quiet
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1

<REDACTED_LAST_PASS>

Correct!
<REDACTED>
```

## Explanation

This service requires an encrypted TLS connection. Plain Netcat is not enough because it does not negotiate TLS. `openssl s_client` can manually connect to TLS-enabled services.

## Key Takeaways

- `openssl s_client` is useful for testing TLS services.
- Not all TCP services speak plaintext.
- TLS-enabled services require TLS-aware clients.

---

# Bandit Level 16 → Level 17

## Objective

Find the correct service running on a port between `31000` and `32000`, submit the current password, and retrieve an SSH private key for the next level.

## Commands

```bash
ssh bandit16@bandit.labs.overthewire.org -p 2220
nmap -p 31000-32000 localhost
```

Run service detection:

```bash
nmap -sV localhost -p 31000-32000
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00018s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
31046/tcp open  echo
31518/tcp open  ssl/echo
31691/tcp open  echo
31790/tcp open  ssl/unknown
31960/tcp open  echo
```

Connect to the SSL-enabled service:

```bash
openssl s_client -connect localhost:31790 -quiet
Can't use SSL_get_servername
depth=0 CN = SnakeOil
verify error:num=18:self-signed certificate
verify return:1
depth=0 CN = SnakeOil
verify return:1

<REDACTED_LAST_PASS>


Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6...
```

Paste the current password. The service returns a private SSH key.

Save the key:

```bash
mkdir /tmp/bandit17_key
cd /tmp/bandit17_key
nano bandit17.key
chmod 600 bandit17.key
```

Use the key:

```bash
ssh -i bandit17.key bandit17@localhost -p 2220
```

## Result

```text
No text password in this one.
```

## Explanation

The level requires scanning a range of local ports and identifying which service accepts the current password over TLS. Once the correct service is found, it returns a private key for `bandit17`.

## Key Takeaways

- `nmap` can scan local ports.
- `-sV` attempts service/version detection.
- SSH private keys must have restrictive permissions.
- `chmod 600` prevents SSH from rejecting the key file.

---

# Bandit Level 17 → Level 18

## Objective

Find the difference between two password files.

## Commands

```bash
ssh bandit17@bandit.labs.overthewire.org -p 2220
ls -la
diff passwords.old passwords.new
```

## Result

```text
42c42
< 390zFj...
---
> x2gLTTj...
```

## Explanation

The home directory contains two files: one old password list and one new password list. The password for the next level is the changed line.

## Key Takeaways

- `diff` compares files line by line.
- Small changes in large files can be found quickly with comparison tools.

---

# Bandit Level 18 → Level 19

## Objective

Read the password from `readme`, even though interactive SSH login immediately closes the session.

## Commands

Instead of opening an interactive shell, run the command directly through SSH:

```bash
ssh bandit18@bandit.labs.overthewire.org -p 2220 cat readme
```

## Result

```text
<REDACTED>
```

## Explanation

The shell for this user exits immediately, preventing normal interaction. However, SSH can execute a remote command directly without opening an interactive session.

## Key Takeaways

- SSH can execute a command remotely.
- Restricted or broken login shells can sometimes be bypassed using direct command execution.
- Interactive shell access is not always required.

---

# Bandit Level 19 → Level 20

## Objective

Use a SUID binary in the home directory to read the password for `bandit20`.

## Commands

```bash
ssh bandit19@bandit.labs.overthewire.org -p 2220
ls -la
./bandit20-do
```

The binary explains its usage. Use it to read the next password:

```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

## Result

```text
<REDACTED>
```

## Explanation

The binary has the SUID bit set and is owned by `bandit20`. When executed, it runs with the effective privileges of its owner. This allows reading files that the current user normally cannot access.

## Key Takeaways

- SUID binaries execute with the permissions of their owner.
- Misconfigured or intentionally exposed SUID binaries can be used for privilege escalation.
- Always inspect home-directory binaries in CTF environments.

---

# Bandit Level 20 → Level 21

## Objective

Use a SUID binary that connects to a local port and compares the received password with the current level password.

## Commands

Start by opening two SSH sessions as `bandit20`.

In the first terminal, start a listener:

```bash
nc -l -p <PORT>
```

Type or send the current password into the listener.

In the second terminal, run:

```bash
./suconnect <PORT>
```

Alternative controlled approach:

Terminal 1:

```bash
echo "<CURRENT_PASSWORD>" | nc -l -p 12345
```

Terminal 2:

```bash
./suconnect 12345
```

## Result

```text
<REDACTED>
```

## Explanation

The `suconnect` binary connects to the given local port. If it receives the correct current password, it outputs the next password.

## Key Takeaways

- `nc -l` can create a local TCP listener.
- Some challenges require coordinating multiple terminal sessions.
- SUID binaries may interact with local services or sockets.

---

# Bandit Level 21 → Level 22

## Objective

Find the password by inspecting cron jobs.

## Commands

```bash
ssh bandit21@bandit.labs.overthewire.org -p 2220
ls -la /etc/cron.d/

cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
```

Inspect the referenced script:

```bash
cat /usr/bin/cronjob_bandit22.sh

	#!/bin/bash
	chmod 644 /tmp/t7O6lds9S...
	cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S...
```

Read the output file identified by the script:

```bash
cat /tmp/<OUTPUT_FILE>
```

## Result

```text
<REDACTED>
```

## Explanation

Cron jobs execute commands automatically at scheduled intervals. The cron configuration reveals a script running as another user. Reading the script shows where the password is written.

## Key Takeaways

- Cron jobs are commonly stored in `/etc/cron.d/`.
- Scripts referenced by cron should be inspected.
- Scheduled tasks can expose useful files or privilege boundaries.

---

# Bandit Level 22 → Level 23

## Objective

Analyze a cron script to determine where the password for `bandit23` is stored.

## Commands

```bash
ssh bandit22@bandit.labs.overthewire.org -p 2220

cat /etc/cron.d/cronjob_bandit23
@reboot bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null
* * * * * bandit23 /usr/bin/cronjob_bandit23.sh  &> /dev/null

cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

The script generates a filename based on an MD5 hash. Reproduce the logic:

```bash
echo I am user bandit23 | md5sum | cut -d ' ' -f 1
```

Use the resulting hash as the filename under `/tmp`:

```bash
cat /tmp/$(echo I am user bandit23 | md5sum | cut -d ' ' -f 1)
```

## Result

```text
<REDACTED>
```

## Explanation

The script writes the password to a file whose name is generated dynamically. By reading the script and reproducing the same command, we can determine the exact file path.

## Key Takeaways

- Bash scripts should be read carefully.
- Dynamic paths can often be reproduced.
- `md5sum` and `cut` are useful for text processing.

---

# Bandit Level 23 → Level 24

## Objective

Exploit a cron job that executes scripts placed in a specific directory.

## Commands

```bash
ssh bandit23@bandit.labs.overthewire.org -p 2220

cat /etc/cron.d/cronjob_bandit24
@reboot bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null
* * * * * bandit24 /usr/bin/cronjob_bandit24.sh &> /dev/null

cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

shopt -s nullglob

myname=$(whoami)

cd /var/spool/"$myname"/foo || exit
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
if [ "$i" != "." ] && [ "$i" != ".." ];
then
echo "Handling $i"
owner="$(stat --format "%U" "./$i")"
if [ "${owner}" = "bandit23" ] && [ -f "$i" ]; then
timeout -s 9 60 "./$i"
fi
rm -rf "./$i"
fi
```

Create a working directory:

```bash
mktemp -d
/tmp/tmp.Z4JFfks...
cd /tmp/tmp.Z4JFfks...
```

Create a script:

```bash
nano script.sh
```

Script content:

```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/bandit23_work/password
```

Set permissions:

```bash
chmod +x script.sh
chmod 777 /tmp/bandit23_work
```

Copy the script to the monitored directory:

```bash
cp script.sh /var/spool/bandit24/foo/
```

Wait for cron to execute it, then read the output:

```bash
cat /tmp/bandit23_work/password
```

## Result

```text
<REDACTED>
```

## Explanation

The cron job runs scripts from a writable directory as `bandit24`. By placing a script there, we can make the cron job read the next password and write it to a location we control.

## Key Takeaways

- Writable cron execution paths can be dangerous.
- Permissions on output directories matter.
- Cron-based execution may require waiting for the next scheduled run.

---

# Bandit Level 24 → Level 25

## Objective

Submit the current password plus a four-digit PIN code to a daemon listening on port `30002`.

## Commands

```bash
ssh bandit24@bandit.labs.overthewire.org -p 2220
```

Generate all possible PIN combinations and send them to the service:

```bash
for i in {0000..9999}; do
  echo "<CURRENT_PASSWORD> $i"
done | nc localhost 30002
```

## Result

```text
<..>
Wrong! Please enter the correct current password and pincode. Try again.
Wrong! Please enter the correct current password and pincode. Try again.
Correct!
The password of user bandit25 is <REDACTED>
```

## Explanation

The service expects the current password followed by a four-digit PIN. Since there are only 10,000 possibilities, a simple brute-force loop is sufficient.

## Key Takeaways

- Bash brace expansion can generate numeric ranges.
- Small keyspaces can be brute-forced locally.
- `nc` can submit generated input to a TCP service.

---

# Bandit Level 25 → Level 26

## Objective

Log in as `bandit26` using an SSH key, then handle a restricted shell environment.

## Commands

```bash
ssh bandit25@bandit.labs.overthewire.org -p 2220
ls -la
cat bandit26.sshkey
```

Inspect the shell assigned to `bandit26`:

```bash
grep bandit26 /etc/passwd
```

Try logging in:

```bash
ssh -i bandit26.sshkey bandit26@localhost -p 2220
```

The session does not behave like a normal shell. The trick is related to the program used as the login shell and the terminal size. Resize the terminal so that the output opens in `more`.

Once inside `more`, open `vim`:

```text
v
```

From inside `vim`, read the password file:

```vim
:e /etc/bandit_pass/bandit26
```

## Result

```text
<REDACTED>
```

## Explanation

The login shell for `bandit26` is not a standard shell. It executes a program that displays text and exits. By forcing the output into a pager and entering `vim`, we can interact with the environment and read the password.

## Key Takeaways

- Not every user has `/bin/bash` as a shell.
- `/etc/passwd` reveals login shells.
- Pagers and editors can sometimes be used to escape restricted environments.

---

# Bandit Level 26 → Level 27

## Objective

Escape the restricted environment and use a SUID binary to read the password for `bandit27`.

## Commands

Log in again using the SSH key from the previous level:

```bash
ssh -i bandit26.sshkey bandit26@localhost -p 2220
```

Force the session into `more`, then press:

```text
v
```

Inside `vim`, set a usable shell:

```vim
:set shell=/bin/bash
```

Spawn the shell:

```vim
:shell
```

Now run:

```bash
ls -la
./bandit27-do cat /etc/bandit_pass/bandit27
```

## Result

```text
<REDACTED>
```

## Explanation

Once inside `vim`, it is possible to configure the shell and spawn it. The home directory contains a SUID binary that can execute commands as `bandit27`, allowing access to the next password.

## Key Takeaways

- `vim` can spawn shells.
- Restricted shell escapes often rely on interactive programs.
- SUID binaries remain useful after escaping a restricted environment.

---

# Bandit Level 27 → Level 28

## Objective

Clone a Git repository over SSH and retrieve the password.

## Commands

This level should be solved from the local machine, not from the Bandit server.

```bash
mkdir /tmp/bandit27_git
cd /tmp/bandit27_git
git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo
```

When prompted, use the password for `bandit27`.

Inspect the repository:

```bash
cd repo
ls -la
cat README
```

## Result

```text
The password to the next level is: <REDACTED>
```

## Explanation

The password is stored in a Git repository accessible over SSH. The Git user uses the same password as the current Bandit level.

## Key Takeaways

- Git can clone repositories over SSH.
- Non-standard SSH ports can be included in the repository URL.
- Repository contents should be inspected after cloning.

---

# Bandit Level 28 → Level 29

## Objective

Find a password hidden in the Git history.

## Commands

```bash
mkdir /tmp/bandit28_git
cd /tmp/bandit28_git
git clone ssh://bandit28-git@bandit.labs.overthewire.org:2220/home/bandit28-git/repo
cd repo
```

Inspect the current files:

```bash
ls -la
cat README.md
```

Inspect the commit history:

```bash
git log
```

Show relevant commits:

```bash
git show <COMMIT_HASH>
```

A compact way to inspect all recent changes:

```bash
git log -p
```

## Result

```text
commit <HASH> (HEAD -> master, origin/master, origin/HEAD)
Author: Morla Porla <morla@overthewire.org>
Date:   Fri Apr 3 15:17:37 2026 +0000

fix info leak

diff --git a/README.md b/README.md
index d4e3b74..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
## credentials

- username: bandit29
-- password: <REDACTED>
+- password: xxxxxxxxxx
```

## Explanation

The current version of the repository may not contain the password, but previous commits can still contain sensitive data. Git preserves history unless it is explicitly rewritten and cleaned.

## Key Takeaways

- Sensitive data can remain in Git history.
- `git log` shows commits.
- `git show` displays the content of a specific commit.
- `git log -p` shows patch-level changes.

---

# Bandit Level 29 → Level 30

## Objective

Find the password in another Git branch.

## Commands

```bash
mkdir /tmp/bandit29_git
cd /tmp/bandit29_git
git clone ssh://bandit29-git@bandit.labs.overthewire.org:2220/home/bandit29-git/repo
cd repo
```

List all branches:

```bash
git branch -a

* master
remotes/origin/HEAD -> origin/master
remotes/origin/dev
remotes/origin/master
remotes/origin/sploits-dev
```

Inspect remote branches:

```bash
git checkout dev
branch 'dev' set up to track 'origin/dev'.
Switched to a new branch 'dev'

cat README.md
```

Alternatively:

```bash
git show origin/<BRANCH_NAME>:README.md
```

## Result

```text
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <REDACTED>
```

## Explanation

The password is not necessarily stored in the default branch. Enumerating all branches reveals additional repository states that may contain the required information.

## Key Takeaways

- `git branch -a` lists local and remote branches.
- Remote branches may contain different files or secrets.
- Always enumerate branches during Git-based challenges.

---

# Bandit Level 30 → Level 31

## Objective

Find the password stored in a Git tag.

## Commands

```bash
mkdir /tmp/bandit30_git
cd /tmp/bandit30_git
git clone ssh://bandit30-git@bandit.labs.overthewire.org:2220/home/bandit30-git/repo
cd repo
```

List tags:

```bash
git tag
```

Show the relevant tag:

```bash
git show <TAG_NAME>
```

## Result

```text
<REDACTED>
```

## Explanation

Git tags are references to specific points in the repository history. Tags can also contain messages or point to commits containing useful information.

## Key Takeaways

- `git tag` lists repository tags.
- `git show <tag>` displays tag content or the referenced object.
- Tags are part of Git enumeration.

---

# Bandit Level 31 → Level 32

## Objective

Push a file to a Git repository according to the instructions in the repository.

## Commands

```bash
mkdir /tmp/bandit31_git
cd /tmp/bandit31_git
git clone ssh://bandit31-git@bandit.labs.overthewire.org:2220/home/bandit31-git/repo
cd repo
```

Read the instructions:

```bash
cat README.md
```

Create the required file:

```bash
echo "May I come in?" > key.txt
```

Check the Git status:

```bash
git status
```

If the file is ignored, force-add it:

```bash
git add -f key.txt
git commit -m "Add key.txt"
git push
```

## Result

```text
remote: ### Attempting to validate files... ####
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote:
remote: Well done! Here is the password for the next level:
remote: <REDACTED>
remote:
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote:
To ssh://bandit.labs.overthewire.org:2220/home/bandit31-git/repo
```

## Explanation

The repository contains instructions requiring a specific file to be pushed. The `.gitignore` file prevents the file from being added normally, so `git add -f` is required.

## Key Takeaways

- `.gitignore` can prevent files from being staged.
- `git add -f` forces Git to add ignored files.
- Some Git challenges require writing to the remote repository, not just reading from it.

---

# Bandit Level 32 → Level 33

## Objective

Escape a shell that converts commands to uppercase.

## Commands

```bash
ssh bandit32@bandit.labs.overthewire.org -p 2220
```

The shell converts typed commands to uppercase, making normal commands fail. Use:

```bash
$0
```

Then run:

```bash
whoami
cat /etc/bandit_pass/bandit33
```

## Result

```text
bandit33: <REDACTED>
```

## Explanation

`$0` expands to the name of the current shell or script. Executing it can spawn a usable shell and bypass the uppercase command restriction.

## Key Takeaways

- Shell variables can be used for escape techniques.
- `$0` often refers to the current shell.
- Restricted command interpreters may still expose unexpected execution paths.

---

# Bandit Level 33 → Level 34

## Objective

Read the final message.

## Commands

```bash
ssh bandit33@bandit.labs.overthewire.org -p 2220
ls -la
cat README.txt
```

## Result

```text
Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new level, please let us know!
```

## Explanation

This is the final Bandit level. Instead of providing another password, the level contains a final message from the OverTheWire team.


---

# Final Notes

Bandit is an excellent introduction to Linux, enumeration, command chaining, file permissions, network services, scheduled tasks, restricted shells, and Git security.

The most important lesson is not memorizing individual commands, but understanding the methodology:

```text
Enumerate → Understand the condition → Choose the right tool → Validate the result
```

Across the wargame, the recurring techniques were:

- Listing and inspecting files.
- Handling unusual filenames.
- Searching by file metadata.
- Filtering large datasets.
- Decoding and decompressing data.
- Interacting with local network services.
- Understanding permissions and SUID behavior.
- Inspecting cron jobs.
- Escaping restricted environments.
- Enumerating Git repositories thoroughly.

From a security perspective, Bandit also demonstrates several real-world issues:

- Secrets stored in files.
- Secrets exposed through Git history.
- Dangerous SUID binaries.
- Overly permissive scheduled task paths.
- Restricted shells that can be escaped through interactive programs.
- Sensitive information exposed through misconfigured local services.