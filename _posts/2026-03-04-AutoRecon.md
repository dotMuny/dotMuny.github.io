---
layout: post
title: AutoRecon
subtitle: A Bash Function for Automated Recon in CTFs and Pentest
date: 2026-03-04 00:00:00
background: ""
tags: [posts]
category: tools
---
![](/img/blog_img/AutoRecon_img/img1.png)

When attacking a machine - whether on HTB, OSCP labs, or a real engagement - the reconnaissance phase sets the tone for everything that follows. A missed port or an overlooked UDP service can mean hours of wasted time. I built `autorecon` to automate and standardize this phase without any external dependencies: just Bash and `nmap`.

## What It Does
`autorecon` runs four sequential stages against a target IP, each building on the previous one:

|Stage|Scan Type|Output File|
|---|---|---|
|1|Fast full TCP (all 65535 ports)|`allPorts`|
|2|Service + default scripts on open ports|`targeted`|
|3|Vulnerability scripts on open ports|`vulns`|
|4|UDP top-1000 + service ID on open UDP|`udp` / `udp_targeted`|

All files land in your current working directory - no subdirectories, no clutter.

## The Function
Add this to your `~/.zshrc` or `~/.bashrc`:

```bash
autorecon() {
    if [ -z "$1" ]; then
        echo -e "\n[!] Usage: autorecon <IP>\n"
        return 1
    fi

    local ip=$1

    # Stage 1: Fast Full TCP Port Scan
    echo -e "\n[*] Stage 1: Fast stealth scan on all TCP ports for $ip..."
    sudo nmap -p- --open --min-rate 5000 -sS -n -Pn \
        -oG allPorts "$ip"

    local ports
    ports=$(grep -oP '\d{1,5}/open' allPorts \
        | awk -F'/' '{print $1}' | xargs | tr ' ' ',')

    if [ -z "$ports" ]; then
        echo -e "\n[!] No open TCP ports detected. Aborting.\n"
        return 1
    fi

    echo -e "\n[+] Open TCP ports: $ports"

    # Stage 2: Targeted Service + Script Scan
    echo -e "[*] Stage 2: Service/script scan (sCV) on discovered ports...\n"
    nmap -sCV -p"$ports" -Pn -vvv \
        -oN targeted "$ip"

    # Stage 3: Vulnerability Scripts
    echo -e "\n[*] Stage 3: Running vuln scripts on discovered ports..."
    nmap --script vuln -p"$ports" -Pn \
        -oN vulns "$ip"
    echo -e "[+] Vulnerability scan complete."

    # Stage 4: UDP Top 1000
    echo -e "[*] Stage 4: UDP scan (top 1000 ports)..."
    sudo nmap -sU --top-ports 1000 -Pn --min-rate 1000 \
        -oN udp "$ip"

    local udp_ports
    udp_ports=$(grep -oP '\d{1,5}/open' udp \
        | awk -F'/' '{print $1}' | xargs | tr ' ' ',')

    if [ -n "$udp_ports" ]; then
        echo -e "[+] Open UDP ports: $udp_ports"
        echo -e "[*] Stage 4b: Service scan on open UDP ports..."
        sudo nmap -sUV -p"$udp_ports" -Pn \
            -oN udp_targeted "$ip"
    else
        echo -e "[!] No open UDP ports found in top 1000."
    fi

    # Summary
    echo -e "\n[+] ══════════ Reconnaissance Complete ══════════"
    echo -e "[+] Target      : $ip"
    echo -e "[+] Files saved :"
    echo -e "      allPorts      → grepable full TCP scan"
    echo -e "      targeted      → service/version/script scan"
    echo -e "      vulns         → vulnerability scripts output"
    echo -e "      udp           → UDP top-1000 scan"
    [ -n "$udp_ports" ] && \
        echo -e "      udp_targeted  → UDP service scan on open ports"
    echo -e "[+] ════════════════════════════════════════════\n"
}
```

<br>

## Stage Breakdown
### Stage 1 - Fast TCP Discovery
```bash
sudo nmap -p- --open --min-rate 5000 -sS -n -Pn -oG allPorts <IP>
```

This is the most critical scan. `-p-` covers all 65535 ports so nothing slips through. `--min-rate 5000` makes it aggressive enough to finish in under a minute on most lab machines. `-sS` (SYN scan) is stealthy and fast. `-n` skips DNS resolution and `-Pn` skips host discovery - both essential when the target doesn't respond to ICMP.

Output is saved in grepable format (`-oG`) so the next stage can parse open ports programmatically.

### Stage 2 - Service and Default Scripts
```bash
nmap -sCV -p<ports> -Pn -vvv -oN targeted <IP>
```

`-sCV` combines version detection (`-sV`) with the default NSE script category (`-sC`). This gets you service banners, HTTP titles, SSL cert details, SMB info, and much more - the foundation for deciding where to dig deeper.

### Stage 3 - Vulnerability Scripts
```bash
nmap --script vuln -p<ports> -Pn -oN vulns <IP>
```

The `vuln` script category runs a curated set of NSE scripts that check for known CVEs and misconfigurations. This includes things like EternalBlue (`ms17-010`), Shellshock, outdated SSL/TLS, anonymous FTP access, and more. It's not a replacement for a dedicated vuln scanner, but it's fast and often surfaces the most obvious wins without any extra tooling.

### Stage 4 - UDP Top 1000

```bash
sudo nmap -sU --top-ports 1000 -Pn --min-rate 1000 -oN udp <IP>
```

UDP is slow and often skipped - which is exactly why it's worth checking. Services like SNMP (161), TFTP (69), DNS (53), and NTP (123) can expose significant attack surface. This stage scans the top 1000 most common UDP ports and, if any are open, follows up with a service scan (`-sUV`) to identify exactly what's running.

## Usage

```bash
autorecon 10.10.11.42
```

That's it. The function handles the rest, printing progress as it goes and listing all output files when complete.

## Workflow Tips

- **Run it from a dedicated folder per machine.** Since all files write to the current directory, I do `mkdir <machinename> && cd <machinename>` before calling `autorecon`.
- **Check `vulns` early.** If Stage 3 flags something like `ms17-010`, you can start working that angle while Stage 4 is still running in a separate terminal.
- **Parse `allPorts` manually if needed.** The grepable format is easy to work with: `grep -oP '\d{1,5}/open' allPorts` gives you a clean list.
- **UDP takes time.** Even with `--min-rate 1000`, UDP scans are slower than TCP. Don't kill it early - SNMP alone has ended many machines.

## Final Thoughts

`autorecon` won't replace deep manual enumeration, but it removes all the repetitive typing at the start of every machine and ensures you never accidentally skip UDP or forget to run vuln scripts. It's been part of my standard workflow for every box since I wrote the first version, and the staged approach means you're already looking at `targeted` output while the slower scans finish in the background.

Feel free to adapt it - add `--script smb-vuln-*` for Windows-heavy labs, or swap `--top-ports 1000` for a specific UDP port list if you have a preferred one.

> **Disclaimer:** This tool is intended for use on machines you own or have explicit authorization to test. Unauthorized scanning is illegal.