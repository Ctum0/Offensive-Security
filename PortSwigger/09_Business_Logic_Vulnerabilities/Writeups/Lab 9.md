# 2FA simple bypass
---
## TARGET
PortSwigger Web Security Academy  
Lab: _2FA simple bypass_
Vulnerability: _Broken Access Control (Forced Browsing / Improper 2FA State Management)_

---
## DESCRIPTION
The application's two-factor authentication (2FA) implementation is superficially enforced. After a user submits valid primary credentials (username and password), the backend immediately issues a fully authenticated session cookie before the user passes the secondary 2FA challenge. An attacker can bypass the 2FA screen entirely by directly navigating to authenticated endpoints.

---
## ROOT CAUSE
**Premature Session Authentication:** The application fails to maintain an intermediate "pending 2FA" state. It fully upgrades the user's session privileges immediately upon Step 1 (password verification). The 2FA screen (Step 2) acts merely as a client-side redirect hurdle rather than a strict server-side access gateway.

---
## ATTACK SCENARIO
1. **Authentication Step 1:** The attacker obtains compromised credentials (`carlos`:`montoya`) and submits them to the `/login` endpoint.
2. **The Hurdle:** The server returns a `200 OK` or `302 Found`, redirecting the user to the `/login2` (2FA verification) page, but simultaneously issues a fully valid `session` cookie.
3. **Forced Browsing (Bypass):** The attacker ignores the `/login2` page and manually changes the URL to a privileged endpoint, such as `/my-account?id=carlos`.
4. **Execution:** Because the session cookie is already fully authorized, the server grants access to the restricted page, completely bypassing the 2FA requirement.

---
## PROOF OF CONCEPT
**njection Point:** `GET /my-account?id=carlos` (Post-login) 
**Payload:** N/A (Direct URL Navigation)
**Retrieval:** Observe the successful rendering of the user's account dashboard.

---
## IMPACT
**Critical:** Full 2FA bypass and Account Takeover. The secondary layer of security is rendered completely ineffective, exposing any account with compromised primary credentials.

---
## FIX / MITIGATION
1. **Strict State Management:** Implement an intermediate authentication state. Upon successful password verification, issue a restricted "pre-auth" token that only grants access to the `/login2` endpoint.
2. **Delayed Privilege Elevation:** Only issue the fully authorized session token _after_ the 2FA challenge has been successfully verified.

---
## KEY LEARNING
**Never grant full privileges prematurely.** Authentication is not complete until all mandated factors are verified. A 2FA page is useless if the backend has already unlocked the vault doors.

---
