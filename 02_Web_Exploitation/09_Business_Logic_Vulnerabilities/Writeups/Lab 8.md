# Password reset broken logic
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Password reset broken logic_
Vulnerability: _Business Logic Flaw (Broken Password Reset)_

---
## DESCRIPTION
The application's password reset functionality relies on a valid, emailed token to authorize a password change. However, it dynamically accepts the `username` parameter in the final `POST` request to determine _which_ account password to overwrite. This allows an attacker to generate a valid reset token for their own account, but apply that token to change the password of any other arbitrary user.

---
## ROOT CAUSE
**Desynchronized State Validation:** The server verifies that the `temp-forgot-password-token` is mathematically valid, but fails to cross-reference it with the user account it was originally issued to. It blindly trusts the client-provided `username` parameter during the database `UPDATE` operation, breaking the cryptographic binding between the token and the account identity.

---
## ATTACK SCENARIO
1. **Token Generation:** The attacker submits a password reset request for their own account (`wiener`).
2. **Token Interception:** The attacker retrieves the valid token from their own email inbox.
3. **Exploitation:** The attacker intercepts the final password reset `POST` request. They leave the valid token intact but change the hidden `username` field from `wiener` to the victim's username (`carlos`).
4. **Bypass:** The server validates the token, accepts the new password, and applies it to `carlos` because the logic dictates updating the account specified in the payload.
5. **Execution:** The attacker logs into the victim's account with the newly set password.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /forgot-password` 
**Payload:**
```HTTP
temp-forgot-password-token=[VALID_WIENER_TOKEN]&username=carlos&new-password-1=tactical_strike&new-password-2=tactical_strike
```
**Retrieval:** Observe the successful redirect, followed by a valid login as `carlos`.

---
## IMPACT
**Critical:** Full Account Takeover. Any user can arbitrarily reset the password of any other user, including administrators, leading to total system compromise.

---
## FIX / MITIGATION
1. **Server-Side State Binding:** Never trust a client-supplied `username` during a password reset. The `username` or `user_id` must be securely derived on the backend _directly_ from the validated reset token.
2. **Drop Superfluous Parameters:** Remove the `username` parameter entirely from the final password reset form submission.

---
## KEY LEARNING
**Tokens must define scope.** A security token is meaningless if it proves authorization but allows the client to dictate the target. The token itself must securely encapsulate exactly _who_ it was issued for.

---
