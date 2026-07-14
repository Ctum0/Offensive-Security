# User ID controlled by request parameter
---
## TARGET
PortSwigger Web Security Academy  
Lab: _User ID controlled by request parameter_
Vulnerability: _Broken Access Control (Insecure Direct Object Reference - IDOR)_

---
## DESCRIPTION
The application allows users to view their account details on the `/my-account` page. This page accepts a user identifier (e.g., `id=wiener`) via a GET parameter to determine which user's information to display. The application fails to verify if the authenticated user is authorized to view the requested profile, allowing access to any user's data by simply modifying the `id` parameter.

---
## ROOT CAUSE
**Insecure Direct Object Reference (IDOR):** The application exposes a direct reference to an internal database object (the user ID) in the URL. It uses this input to retrieve data without performing an authorization check to ensure the session owner matches the requested identity.

---
## ATTACK SCENARIO
1. **Authentication:** The attacker logs in with valid credentials (`wiener:peter`).
2. **Reconnaissance:** The attacker navigates to the "My Account" page and observes the URL structure: `/my-account?id=wiener`.
3. **Tampering:** The attacker modifies the `id` parameter in the URL from `wiener` to the victim's username, `carlos`.
4. **Exploitation:** The server processes the request and returns the account details for `carlos`, including his sensitive API key.
5. **Exfiltration:** The attacker copies the API key and submits it to solve the lab.

---
## PROOF OF CONCEPT
**Injection Point:** URL Parameter `id` **Payload:** `carlos`
**Manual Exploit Request:**
```HTTP
GET /my-account?id=carlos HTTP/1.1
Host: <LAB-ID>.web-security-academy.net
Cookie: session=WIENER_SESSION_COOKIE
```

**Retrieval (Response Excerpt):**
```HTML
<div id="account-content">
    Your API Key is: zx82... (Carlos's Key)
</div>
```

---
## IMPACT
**High:** Horizontal Privilege Escalation. An authenticated user can access the private account information (API keys, PII) of any other user on the platform.

---
## FIX / MITIGATION
1. **Session-Based Retrieval:** Remove the `id` parameter entirely. Retrieve the user's profile based solely on the secure, server-side session ID.
2. **Authorization Check:** If the parameter is necessary, validate that `request.user.id == target.id` before returning data.

---
## KEY LEARNING
**Trust the Session, Not the URL.** Never rely on user-supplied parameters (like `id=wiener`) to determine "who" is logged in. Identity must be derived from the secure session token. If you must use an ID, enforce strict ownership checks.

---
