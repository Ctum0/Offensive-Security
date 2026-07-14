# User ID controlled by request parameter, with unpredictable user IDs
---
## TARGET
PortSwigger Web Security Academy  
Lab: _User ID controlled by request parameter, with unpredictable user IDs_
Vulnerability: _Broken Access Control (IDOR with GUIDs)_

---
## DESCRIPTION
The application uses a specific parameter (GUID) to identify users on the account page (`/my-account?id=GUID`). While GUIDs are generally impossible to guess, the application discloses the GUIDs of other users publicly on the blog. The application fails to verify if the session owner matches the requested GUID, allowing unauthorized access to other users' accounts.

---
## ROOT CAUSE
**Information Disclosure & Missing Authorization:**
1. **Information Disclosure:** The application leaks the sensitive User ID (GUID) in public areas, specifically in the "Author" link of blog posts.
2. **IDOR:** The `/my-account` endpoint trusts the `id` parameter provided in the URL without verifying that it belongs to the currently authenticated user.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker browses the public blog to find a post written by the victim, `carlos`.
2. **Extraction:** The attacker clicks on the author name "Carlos" or inspects the link, observing the URL format: `/blogs?userId=29d1b...`. This reveals Carlos's GUID.
3. **Exploitation:** The attacker navigates to their own account page (`/my-account`), captures the request, and replaces their own `id` parameter with Carlos's GUID.
4. **Exfiltration:** The server returns Carlos's account page, allowing the attacker to steal his API key.

---
## PROOF OF CONCEPT
**1. Disclosure URL (Blog):**
```HTTP
GET /blogs?userId=carlos-guid-here HTTP/1.1
```

**2. Exploit Request:**
```HTTP
GET /my-account?id=carlos-guid-here HTTP/1.1
Host: <LAB-ID>.web-security-academy.net
Cookie: session=WIENER_SESSION_TOKEN
```

---
## IMPACT
**High:** Horizontal Privilege Escalation. An attacker can access sensitive account details (PII, API Keys) of any user who has published content on the site.

---
## FIX / MITIGATION
1. **Session-Based Identity:** Do not rely on client-side parameters for identity. Retrieve the profile based on the authenticated session ID stored on the server.
2. **Decouple Public/Private IDs:** If a public ID is needed for blog posts, use a separate identifier (e.g., `username`) that does not map directly to the internal ID used for account management, or strictly validate authorization on the account page.

---
## KEY LEARNING
**Unpredictable ≠ Secret.** Using GUIDs prevents _guessing_ (Enumeration), but it does not prevent Access Control attacks if the GUID is leaked elsewhere in the application. Always assume IDs will be discovered.

---
