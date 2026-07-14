# File path traversal, validation of start of path
---
## TARGET
PortSwigger Web Security Academy  
Lab: _File path traversal, validation of start of path_

---
## DESCRIPTION
The application contains a path traversal vulnerability in the display of product images. The application transmits the full file path via a request parameter. To prevent unauthorized access, it validates that the supplied path strictly **starts with** the expected folder (e.g., `/var/www/images/`). The goal is to retrieve the contents of the `/etc/passwd` file.

---
## ROOT CAUSE
**Weak Validation (Prefix Check):** The application validates the input using a "starts with" logic (e.g., `if path.startswith("/var/www/images/")`). It fails to validate the rest of the path, allowing an attacker to append traversal sequences (`../`) to step out of the required directory immediately after entering it.

---
## ATTACK SCENARIO
1. **Identification:** The attacker observes the `filename` parameter uses absolute paths: `/var/www/images/15.jpg`.
2. **Hypothesis:** The attacker attempts to change the path to `/etc/passwd` but is blocked. They suspect the server requires the original directory path to be present.
3. **Bypass:** The attacker constructs a path that begins with the required folder but uses `../` to traverse back out.
    - Path: `/var/www/images/` (Satisfies check) + `../../../` (Goes to root) + `etc/passwd`.
4. **Injection:** The attacker submits `/var/www/images/../../../etc/passwd`.
5. **Result:** The application validates the prefix, then the operating system resolves the traversal, serving the password file.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/image`
- **Parameter:** `filename`
- **Method:** GET
### Payload Used
```
/var/www/images/../../../etc/passwd
```
### Response Snippet
```
root:x:0:0:root:/root:/bin/bash
...
```

---
## IMPACT
**High.** Allows reading of arbitrary files on the server.

---
## FIX / MITIGATION
- **Canonicalization:** Resolve the path to its absolute form (removing all `../` and symbolic links) _before_ performing the "starts with" check.
- **Strict Allowlist:** If possible, do not allow the user to supply paths at all. Use an ID map.

---
## KEY LEARNING
- **Prefix != Safety:** Checking the start of a string is useless if the underlying system (the filesystem) allows "backtracking" later in the string.
- **Context Matters:** `/var/www/images/../` is effectively just `/var/www/`.

---
