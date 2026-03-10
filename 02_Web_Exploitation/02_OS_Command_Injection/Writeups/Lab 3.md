# Blind OS command injection with output redirection
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Blind OS command injection with output redirection_

---
## DESCRIPTION
The application contains a blind OS command injection vulnerability in the feedback function. While it does not return command output directly in the response, the application serves static images from a writable directory (`/var/www/images/`). The goal is to redirect command output to a file in this directory and retrieve it via the web server.

---
## ROOT CAUSE
1. **Unsanitized Input:** The `email` field is passed to a shell command without validation.
2. **Weak File Permissions:** The web server user has write permissions to a directory (`/var/www/images/`) that is also accessible via the web interface.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker notes that product images are loaded via a URL parameter (e.g., `/image?filename=1.jpg`) and serves files from `/var/www/images/`.
2. **Injection:** The attacker submits feedback with a payload designed to write data to that folder.
    - Payload: `|| whoami > /var/www/images/output.txt ||`
    - _Logic:_ The `>` operator redirects the standard output (stdout) of `whoami` into the specified file.
3. **Retrieval:** The attacker navigates to `/image?filename=output.txt`.
4. **Result:** The server reads the created file and displays the username (`peter-gjZSZL`).

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/feedback/submit`
- **Method:** POST
- **Parameter:** `email`
### Payload Used
```
|| whoami > /var/www/images/hack.txt ||
```
### Retrieval Point
- **URL:** `/image?filename=pwned.txt`
- **Method:** GET

---
## IMPACT
- **Remote Code Execution (RCE):** The attacker has full control over the web server application.
- **Web Defacement:** Since the attacker can write to the public image folder, they can overwrite legitimate images with malicious or offensive content.
- **Persistency:** The attacker can drop permanent backdoors (webshells) into the accessible web root.

---
## FIX / MITIGATION
- **Read-Only Filesystem:** Run the web application with a user that has **Read-Only** access to the web root.
- **Input Validation:** Strictly allow-list input characters (e.g., email regex only).
- **Indirect Object References:** Do not allow users to specify filenames directly in the URL (e.g., use IDs like `?id=1` mapped to filenames database-side).

---
## KEY LEARNING
- **The Filesystem as a Side Channel:** When you cannot see the output directly (Blind) and you cannot connect back to your own server (Firewall/OOB blocked), the server's own filesystem becomes your communication channel.
- **Web Root Danger:** Writing to `/var/www/images/` is dangerous because the web server is _designed_ to share files from that folder publicly. This converts a "Blind" RCE into a fully visible one.

---
