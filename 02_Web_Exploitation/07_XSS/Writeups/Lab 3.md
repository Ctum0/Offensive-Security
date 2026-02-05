# Reflected XSS into HTML Context (Most Tags Blocked)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Reflected XSS into HTML context with most tags and attributes blocked_
Vulnerability: _Reflected Cross-Site Scripting (XSS) with WAF Bypass_

---
## DESCRIPTION
The application contains a reflected XSS vulnerability in the search function. However, a Web Application Firewall (WAF) is deployed that blocks most common HTML tags (like `<script>`, `<img>`, `<svg>`) and event handlers (like `onload`, `onerror`). The goal is to identify the allowed syntax and construct a payload that triggers `print()`.

---
## ROOT CAUSE
**Incomplete Denylist (WAF Bypass):** The WAF relies on a "Denylist" approach, blocking known bad words. It fails to block the `<body>` tag and the `onresize` event handler. This allows an attacker to inject an executable vector that doesn't match the WAF's block signatures.

---
## ATTACK SCENARIO
1. **Reconnaissance (Fuzzing):**
    - The attacker fuzzes standard HTML tags against the WAF. The server returns `400 Bad Request` for most, but returns `200 OK` for the `<body>` tag.
    - The attacker fuzzes event attributes on the `<body>` tag. The WAF blocks `onload` and `onerror`, but allows `onresize`.
2. **Weaponization:**
    - Since `onresize` requires the window dimensions to change, the attacker cannot rely on user interaction.
    - The attacker constructs an **Iframe Exploit**: `<iframe src=".../?search=<body onresize=print()>" onload="this.style.width='100px'">`.    
3. **Delivery:** The attacker hosts this iframe on an external site (Exploit Server) and sends the link to the victim.
4. **Execution:** When the victim visits the attacker's site, the iframe loads the search page. The iframe's `onload` event immediately resizes the frame, triggering the `onresize` event inside the search page, executing `print()`.

---
## PROOF OF CONCEPT
### Bypass Vector
- **Tag:** `<body>`
- **Attribute:** `onresize`
### Exploit Code
```html
<iframe src="https:///0a8b0023032bcfe0815f849a005500d9.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'></iframe>
```

---
## IMPACT
**Medium:** Despite the WAF, an attacker can still execute arbitrary JavaScript. The requirement to use `onresize` makes the exploit slightly more complex (requires framing), but the impact remains the same: potential session hijacking or redirection.

---
## FIX / MITIGATION
1. **Positive Security Model (Allowlist):** Instead of blocking "Bad" tags, only allow specific "Good" characters (e.g., alphanumeric only).
2. **HTML Encoding:** Encode all user input before reflecting it, regardless of the tag used. `<body>` should become `&lt;body&gt;`.

---
## KEY LEARNING
**WAFs are not patches.** A Web Application Firewall often just checks for specific strings (`<script>`, `onerror`). It does not fix the underlying code vulnerability. If you can find _one_ tag and _one_ event handler that the developer forgot to ban, you can completely bypass the protection. Fuzzing is the primary tool for this.

---
