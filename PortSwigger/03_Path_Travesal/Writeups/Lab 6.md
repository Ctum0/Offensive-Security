# File path traversal, validation of file extension with null byte bypass
---
## TARGET
PortSwigger Web Security Academy  
Lab: _File path traversal, validation of file extension with null byte bypass_

---
## DESCRIPTION
The application contains a path traversal vulnerability in the display of product images. The application validates input by ensuring the supplied filename ends with a specific expected extension (e.g., `.jpg` or `.png`). The goal is to retrieve the contents of the `/etc/passwd` file.

---
## ROOT CAUSE
**Null Byte Injection:** The application is likely built on a high-level language (like Java or PHP) that passes the string to a low-level API (C/C++) for file retrieval.
- **The Validator:** Checks if the string _ends with_ `.png`.
- **The Filesystem:** Interprets the Null Byte (`%00`) as a string terminator. It reads until it hits `%00` and ignores any characters following it. 

---
## ATTACK SCENARIO
1. **Identification:** The attacker observes that the filename parameter requires a `.png` extension. Removing it causes an error ("Invalid file type").
2. **Hypothesis:** The attacker attempts to append the extension to a malicious path: `../../../etc/passwd.png`. This fails because the file `passwd.png` does not exist.
3. **Bypass:** The attacker injects a Null Byte before the extension.
    - Payload: `../../../etc/passwd%00.png`
4. **Execution:**
    - **Validator:** Sees `...passwd%00.png`. "Ends with .png? YES." -> **PASS**.
    - **OS/Filesystem:** Reads `...passwd`. Hits `%00` (Stop). -> **READS /etc/passwd**.
5. **Result:** The password file is returned.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/image`
- **Parameter:** `filename`
- **Method:** GET
### Payload Used
```
../../../etc/passwd%00.png
```
(The validator sees a .png file, but the system reads up to the null byte)
### Response Snippet
```
root:x:0:0:root:/root:/bin/bash
...
```

---
## IMPACT
**High.** Allows reading of arbitrary files on the server by bypassing extension filters.

---
## FIX / MITIGATION
- **Reject Null Bytes:** The application should reject any input containing `%00` or the null character.
- **High-Level APIs:** Use modern filesystem APIs that do not treat null bytes as terminators (e.g., modern Python or Java usually throw an error if a null byte is present in a path).

---
## KEY LEARNING
- **The "Terminator":** In C and C++, strings are "null-terminated". The computer doesn't know how long a string is; it just reads until it sees a 0 (Null).
- **Legacy Flaw:** This vulnerability is becoming rarer in modern web frameworks but is still common in legacy systems or Perl/PHP backends.

---
