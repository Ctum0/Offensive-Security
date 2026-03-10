# Weak isolation on dual-use endpoint
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Weak isolation on dual-use endpoint_
Vulnerability: _Business Logic Flaw (Privilege Escalation via Parameter Injection)_

---
## DESCRIPTION
The application utilizes a single, dual-use API endpoint (`/my-account/change-password`) to handle both standard user password changes and administrative password overrides. The backend determines which code path to execute based on the parameters provided in the HTTP request rather than the actual privilege level of the authenticated session. By manually injecting a `username` parameter into a standard password change request, an attacker can trigger the administrative code path and force a password reset on any arbitrary account.

---
## ROOT CAUSE
**Parameter-Based Privilege Inference:** The server fails to strictly enforce Role-Based Access Control (RBAC) bound to the server-side session. It makes a flawed assumption: if the `username` parameter is present in the request, the application assumes the request is coming from an administrator managing another user, and bypasses the `current-password` validation check.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker logs in as a standard user (`wiener`) and initiates a normal password change.
2. **Interception:** The attacker intercepts the `POST` request to `/my-account/change-password`.
3. **Manipulation:** The attacker removes the `current-password` parameter (required for standard users) and injects `username=administrator` alongside the new password fields.
4. **Bypass:** The backend logic detects the `username` parameter, switches to the administrator context, and overrides the target's password without requiring the original password.
5. **Execution:** The attacker logs into the `administrator` account using the newly set password and gains full system control.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /my-account/change-password`
**Payload:**
```HTTP
csrf=[TOKEN]&username=administrator&new-password-1=hello&new-password-2=hello
```
**Retrieval:** Observe the `Password changed successfully!` response, followed by a successful login as `administrator`.

---
## IMPACT
**Critical:** Full Account Takeover and Privilege Escalation. Any low-privileged user can systematically lock out and compromise all accounts on the platform, including administrators.

---
## FIX / MITIGATION
1. **Endpoint Segregation:** Separate administrative functions and user functions into entirely distinct API endpoints (e.g., `/admin/change-password` vs `/my-account/change-password`).
2. **Strict Session Binding:** Never infer a user's role or intent based on client-controllable input (like the presence of a `username` parameter). Authorization must be validated exclusively against the trusted, server-side session object.

---
## KEY LEARNING
**Dual-use endpoints are a security liability.** Combining standard and administrative logic into a single function creates branching paths that are highly susceptible to parameter tampering. Keep logic paths isolated and strictly authenticated.

---
