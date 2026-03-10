# File path traversal, traversal sequences blocked with absolute path bypass
---
## TARGET
PortSwigger Web Security Academy  
Lab: _File path traversal, traversal sequences blocked with absolute path bypass_

---
## DESCRIPTION
The application contains a path traversal vulnerability in the display of product images. It attempts to block traversal attacks by filtering or rejecting sequences like `../`. However, it treats the supplied filename as being relative to a default working directory _unless_ an absolute path is provided. The goal is to retrieve the contents of the `/etc/passwd` file.

---
## ROOT CAUSE
**Flawed Input Validation (Blacklisting):** The developer likely implemented a check that looks specifically for `../` characters to prevent moving "up" directories. They failed to account for **Absolute Paths** (paths starting with `/`), which tell the operating system to ignore the current working directory and start from the root.

---
## ATTACK SCENARIO
1. **Identification:** The attacker attempts a standard traversal (`../../../etc/passwd`) and finds it blocked (likely a "File not found" or security error).
2. **Bypass:** The attacker hypothesizes that the application accepts full file paths.
3. **Injection:** The attacker submits `/etc/passwd` as the filename.
4. **Execution:** The server receives the absolute path. Since it starts with `/`, the operating system treats it as a full path, ignoring the application's intended image directory.
5. **Result:** The contents of `/etc/passwd` are returned.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/image`
- **Parameter:** `filename`
- **Method:** GET
### Payload Used
```
/etc/passwd
```
(Note: No `../` sequences used.)
### Response Snippet
```
root:x:0:0:root:/root:/bin/bash
...
```

---
## IMPACT
**High.** Allows reading of arbitrary files on the server (configuration, source code, system files), leading to potential full system compromise.

---
## FIX / MITIGATION
- **Avoid Blacklisting:** Do not rely on stripping specific characters like `../`. Attackers will find other ways (absolute paths, encoding, etc.).

- **Canonicalization:** Use a function (like `os.path.abspath` in Python or `realpath` in PHP) to resolve the user's input to its final path. Then, check if that final path starts with the expected secure directory (e.g., `/var/www/images/`).
---
## KEY LEARNING
- **Absolute vs. Relative:** Security filters often focus too much on "climbing out" (relative traversal) and forget that an attacker might just "teleport" to the target (absolute path).
- **Blacklists Fail:** Blocking `../` is rarely enough.
---
