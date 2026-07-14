# File path traversal, traversal sequences stripped non-recursively
---
## TARGET
PortSwigger Web Security Academy  
Lab: _File path traversal, traversal sequences stripped non-recursively_

---
## DESCRIPTION
The application contains a path traversal vulnerability in the display of product images. It attempts to sanitize user input by stripping path traversal sequences (`../`). However, the stripping mechanism is **non-recursive**, meaning it only runs once. The goal is to retrieve the contents of the `/etc/passwd` file.

---
## ROOT CAUSE
**Flawed Sanitization (Non-Recursive):** The application removes the `../` pattern from the input string but fails to check the _resulting_ string. If an attacker nests the sequence (e.g., `....//`), removing the inner `../` causes the remaining characters to merge and form a new `../` sequence, which is then processed by the filesystem.

---
## ATTACK SCENARIO
1. **Identification:** The attacker attempts a standard traversal (`../../../`) and finds it blocked.
2. **Hypothesis:** The attacker suspects the application is stripping the `../` sequence.
3. **Bypass:** The attacker crafts a payload using **nested** sequences: `....//`.
    - _Logic:_ `..` + `../` + `/` -> The filter removes the middle `../`. -> The remaining `..` and `/` join to form `../`.
4. **Injection:** The attacker submits `filename=....//....//....//etc/passwd`.
5. **Result:** The server reconstructs the valid traversal path and returns the contents of `/etc/passwd`.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/image`
- **Parameter:** `filename`
- **Method:** GET
### Payload Used
```
....//....//....//etc/passwd
```
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
- **Canonicalization (Best Practice):** Resolve the path to its absolute form (using `realpath` or `abspath`) and check if it starts with the expected base directory.
- **Recursive Filtering:** If stripping is necessary, loop the removal function until the pattern no longer exists in the string (though this is still prone to errors).
- **Whitelist:** Validate that the input contains only safe characters (e.g., alphanumeric and a single dot).

---
## KEY LEARNING
- **Sanitization vs. Validation:** Trying to "clean" bad input is much harder than just checking if the input matches a "good" pattern.
- **The "Merge" Effect:** Whenever you remove characters from a string, you risk bringing separated characters together to form a new, malicious pattern.

---
