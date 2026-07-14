# Multi-step process with no access control on one step
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Multi-step process with no access control on one step_
Vulnerability: _Broken Access Control (Workflow Bypass)_

---
## DESCRIPTION
The application implements an administrative function to upgrade user roles using a multi-step process. The first step (likely a confirmation page) restricts access to administrators. However, the second step—the actual `POST` request that commits the change—fails to verify the user's permissions. It assumes that anyone reaching this step has successfully passed the previous access control check.

---
## ROOT CAUSE
**Incomplete Authorization & State Assumptions:** The developers enforced access control on the _initial_ step (the UI view) but neglected to enforce it on the _final_ step (the action). The server trusts the client-side workflow sequence instead of validating the authorization token on every distinct request.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker logs in as an administrator to map the upgrade workflow. They capture the traffic and identify the `POST /admin-roles` request.
2. **Analysis:** The attacker observes that the request contains parameters like `action=upgrade` and `confirmed=true`.
3. **Exploitation:** The attacker logs in as a low-privileged user (`wiener`).
4. **Bypass:** The attacker sends the captured `POST` request directly to the server using their own session cookie, skipping the restricted confirmation page.
5. **Result:** The server processes the request, and `wiener` is promoted to administrator.

---
## PROOF OF CONCEPT
**Vulnerable Request:**
```HTTP
POST /admin-roles HTTP/1.1
Host: <LAB-ID>.web-security-academy.net
Cookie: session=WIENER_SESSION
Content-Type: application/x-www-form-urlencoded

action=upgrade&confirmed=true&username=wiener
```

---
## IMPACT
**Critical:** Unauthorized Privilege Escalation. Any authenticated user can grant themselves administrative rights, leading to full system compromise.

---
## FIX / MITIGATION
1. **Defense in Depth:** Enforce access control checks on **every** request, regardless of where it falls in a multi-step sequence.
2. **Stateless Security:** Do not rely on the user having visited "Step 1" to authorize "Step 2". Treat every HTTP request as independent and requiring validation.

---
## KEY LEARNING
**Every Endpoint is an Entry Point.** Attackers do not follow your UI flow. They can send requests directly to any endpoint in any order. If a sensitive action (like `delete` or `upgrade`) relies on a previous page for security, it is vulnerable.

---
