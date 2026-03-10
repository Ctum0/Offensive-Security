# File path traversal, simple case
---
## TARGET
PortSwigger Web Security Academy  
Lab: _File path traversal, simple case_

---
## DESCRIPTION
The application contains a path traversal vulnerability in the display of product images. The application takes a user-supplied filename and retrieves it from the server's filesystem without sufficient validation. The goal is to retrieve the contents of the `/etc/passwd` file.

---
## ROOT CAUSE
**Insufficient Input Validation:** The application likely uses a line of code similar to `open("/var/www/images/" + filename)`. It fails to sanitize or strip traversal sequences (`../`), allowing the user to step out of the intended directory and access the root filesystem.

---
## ATTACK SCENARIO
1. **Identification:** The attacker observes that product images are loaded via a query parameter: `/image?filename=72.jpg`.
2. **Injection:** The attacker modifies the `filename` parameter, replacing the image name with a traversal payload.
    - **Payload:** `../../../etc/passwd`
3. **Execution:** The server resolves the path `../` recursively to reach the root directory (`/`), then reads `etc/passwd`.
4. **Result:** The application returns the contents of the password file in the HTTP response.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/image`
- **Parameter:** `filename`
- **Method:** GET
### Payload Used
```
../../../etc/passwd
```
### Response Snippet
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

---
## IMPACT
**High.** An attacker can read arbitrary files on the server. This includes:
- **Configuration files:** (e.g., database credentials).
- **Source code:** (revealing logic and other vulnerabilities).
- **System files:** (`/etc/passwd`, `/etc/hosts`) which aid in further compromise.
---
## FIX / MITIGATION
- **Input Validation:** Whitelist allowed characters (e.g., alphanumeric only).
- **Indirect Object References:** Use database IDs (e.g., `?id=123`) mapped to filenames on the backend, rather than exposing actual filenames.
- **Canonicalization:** Resolve the path to its absolute form and verify it starts with the expected base directory _before_ reading the file.

---
## KEY LEARNING
- **The "Simple" Case:** This indicates a complete lack of filters. The application blindly trusts the input.
- **Depth:** We typically use three or four `../` sequences (`../../../`) to ensure we reach the root directory from wherever the web server is running (usually `/var/www/html`).

---
