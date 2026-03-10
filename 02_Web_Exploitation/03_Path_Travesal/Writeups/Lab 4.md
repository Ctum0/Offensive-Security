# File path traversal, traversal sequences stripped with superfluous URL-decode
---
## TARGET
PortSwigger Web Security Academy  
Lab: _File path traversal, traversal sequences stripped with superfluous URL-decode_

---
## DESCRIPTION
The application contains a path traversal vulnerability in the display of product images. The application attempts to block traversal sequences, but it performs a **URL-decode** operation on the input _after_ the security check has already run. This allows an attacker to use **Double URL Encoding** to smuggle the malicious payload past the filter.

---
## ROOT CAUSE
**Incorrect Order of Operations (TOCTOU):** The application likely follows this flawed logic:
1. **Decode Input:** (Standard web server behavior).
2. **Security Check:** Look for `../`. (If the attacker sends `%2e%2e%2f`, it is decoded to `../` here and blocked).
3. **Superfluous Decode:** The application manually decodes the input _again_.
4. **Use Input:** The file is accessed.
By Double Encoding (`%252e%252e%252f`), the first decode turns it into Single Encoded (`%2e%2e%2f`). The security filter sees `%2e...` (which does not match `../`) and lets it pass. The second decode turns it into `../`, executing the attack.

---
## ATTACK SCENARIO
1. **Identification:** Standard traversal (`../`) and single-encoded traversal (`%2e%2e%2f`) are blocked.
2. **Hypothesis:** The attacker suspects the server might be decoding input multiple times or the WAF/Filter only decodes once.
3. **Bypass:** The attacker double-encodes the characters.
    - `../` -> `%2e%2e%2f` -> `%252e%252e%252f`
4. **Injection:** The attacker submits the double-encoded string.
5. **Result:** The application decodes it down to the traversal sequence and retrieves `/etc/passwd`.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/image`
- **Parameter:** `filename`
- **Method:** GET
### Payload Used
```
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```
(Decodes to `../../../etc/passwd`)
### Response Snippet
```
root:x:0:0:root:/root:/bin/bash
...
```

---
## IMPACT
**High.** Allows reading of arbitrary files on the server (configuration, source code, system files), bypassing the developer's intended security filter.

---
## FIX / MITIGATION
- **Decode First, Then Validate:** Always perform all decoding steps _before_ running security filters.
- **Avoid Manual Decoding:** Do not manually call URL-decode functions on input that the web server has already decoded unless absolutely necessary.
- **Reject Double Encoding:** Configure the WAF or application to reject inputs that appear to be double-encoded.

---
## KEY LEARNING
- **Layers of Interpretation:** Security controls often fail because different parts of the stack (WAF, Web Server, App Code) interpret data differently.
- **Encoding Math:** `%25` is the URL encoding for `%`. By adding `%25` before any hex code, you are effectively "wrapping" it in a protective layer that requires an extra decode step to unwrap.
---
