# 2FA broken logic
---
## TARGET
PortSwigger Web Security Academy  
Lab: _2FA broken logic_
Vulnerability: _Broken Authentication (Flawed Multi-Factor Authentication Logic)_

---
## DESCRIPTION
The application's two-factor authentication (2FA) mechanism relies on a client-controllable cookie (`verify`) to determine which user account is actively being verified. This disconnects the MFA challenge from the initial password verification state, allowing an attacker to generate and brute-force 2FA codes for any user without knowing their password.

---
## ROOT CAUSE
**Insecure State Management:** The server fails to cryptographically bind the 2FA verification phase to a secure, server-side session variable established during the first login step. Instead, it blindly trusts the `verify` cookie provided by the client.

---
## ATTACK SCENARIO
1. **Authentication:** The attacker logs in with their own credentials to access the 2FA portal.
2. **Trigger:** The attacker intercepts a request to `/login2` and alters the `verify` cookie to the victim's username (`carlos`). This forces the server to generate a 2FA code for the victim.
3. **Brute-Force:** The attacker uses an automated script or tool (like Burp Intruder) to send `POST` requests to `/login2`, iterating through all possible 4-digit MFA codes (0000-9999) while maintaining the victim's `verify` cookie.
4. **Bypass:** Upon submitting the correct code, the server issues a valid session cookie for the victim's account.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /login2` 
**Payload:**
```HTTP
Cookie: verify=carlos
mfa-code=[0000-9999]
```
**Retrieval:** Capture the `Set-Cookie: session=...` header upon receiving an HTTP `302 Found` response.

---
## IMPACT
**Critical:** Full Account Takeover. An attacker can bypass 2FA for any user on the platform, nullifying the security benefits of multi-factor authentication.

---
## FIX / MITIGATION
1. **Server-Side State Binding:** Store the pending 2FA authentication state securely on the server (e.g., in a temporary session object) tied to the successful password submission.
2. **Remove Client Control:** Never rely on user-modifiable cookies or hidden form fields to determine the target of a sensitive security operation.

---
## KEY LEARNING
**Do not fragment authentication.** Authentication is a continuous chain. If Step 2 (MFA) does not cryptographically verify that Step 1 (Password) was successfully completed by the _same entity_ for the _same account_, the chain is broken.

---
