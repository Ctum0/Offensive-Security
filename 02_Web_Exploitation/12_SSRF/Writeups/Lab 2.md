# SSRF with blacklist-based input filter
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SSRF with blacklist-based input filter_
Vulnerability: _Server-Side Request Forgery (SSRF)_

---
## DESCRIPTION
The application contains a Server-Side Request Forgery (SSRF) vulnerability within its stock check feature. While the system employs a blacklist to block common local IP addresses and administrative endpoints, these defenses are fundamentally insufficient. An attacker can circumvent the blacklist by utilizing IP obfuscation and double URL encoding to access the local administrative interface and forcefully delete a target user.

---
## ROOT CAUSE
The application implements a flawed, blacklist-based input validation mechanism and fails to normalize the input before validation. Consequently, an attacker can bypass the filter because the backend routing system decodes the payload an additional time after the initial security check has already permitted the request.

---
## ATTACK SCENARIO
- Intercepts the stock check HTTP POST request.
- Replaces the `stockApi` URL with `http://127.1/` to bypass the `127.0.0.1` IP string-matching filter.
- Attempts to access the `/admin` path and observes the request is blocked by a secondary blacklist filter.
- Obfuscates the target endpoint by double-URL encoding the character "a" resulting in the payload `%2561dmin`.
- Forwards the modified request, successfully bypassing the validation check and accessing the administrative panel.
- Executes the internal deletion endpoint to permanently remove the victim user account.

---
## PROOF OF CONCEPT
Target Endpoint: `POST /product/stock`
Exploit Payload: 
```HTTP
stockApi=http://127.1/%2561dmin/delete?username=carlos
```
---
## IMPACT
This vulnerability results in a complete bypass of perimeter security controls. It leads to unauthorized access to internal administrative functions, enabling critical privilege escalation and arbitrary account deletion.

---
## FIX / MITIGATION
Eradicate the blacklist approach and implement a strict, mathematically defined allowlist of permitted external domains. Ensure that all user-supplied input is fully normalized and decoded _before_ any security validation checks are performed.

---
## KEY LEARNING
Blacklists are inherently flawed and easily bypassed via obfuscation; security controls must rely on strict allowlists and enforce input normalization prior to validation.

---
