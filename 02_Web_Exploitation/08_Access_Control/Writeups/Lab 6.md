# Method-based access control can be circumvented
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Method-based access control can be circumvented_
Vulnerability: _Broken Access Control (HTTP Method Bypass)_

---
## DESCRIPTION
The application implements role-based access control to prevent unauthorized users from accessing the administrative function `/admin-roles`. However, the access control filter specifically targets the `POST` method used by the interface. The application framework inadvertently handles alternative HTTP methods (like `GET`) for the same route without applying the same security restrictions.

---
## ROOT CAUSE
**Incomplete Security Filtering (Method Blindness):** The security controls are tightly coupled to the HTTP method (`POST`) rather than the resource itself. The developers failed to account for framework behaviors that map multiple HTTP verbs (GET, POST, HEAD) to the same backend logic, creating a backdoor for unauthorized access.

---
## ATTACK SCENARIO
1. **Reconnaissance (Admin):** The attacker logs in as an administrator to understand the upgrade functionality. They capture the `POST /admin-roles` request used to promote a user.
2. **Session Acquisition (Attacker):** The attacker logs in with their own low-privileged account (`wiener`) and copies their valid session cookie.
3. **Tampering:** In a proxy tool (Burp Repeater), the attacker takes the Admin's `POST` request and **replaces the Admin's session cookie with Wiener's session cookie** to test authorization.
4. **Verification (Blocked):** Sending the `POST` request with Wiener's cookie results in `403 Forbidden` or `401 Unauthorized`, confirming that the standard path is protected.
5. **Bypass:** The attacker changes the request method from `POST` to `GET` (converting body parameters to URL query parameters).
6. **Exploitation:** The server processes the `GET` request without triggering the security filter, and `wiener` is promoted to administrator.

---
## PROOF OF CONCEPT
**1. Capture Admin Request (Template):**
```HTTP
POST /admin-roles HTTP/1.1
Cookie: session=ADMIN_SESSION_TOKEN
Content-Type: application/x-www-form-urlencoded

username=carlos&action=upgrade
```

**2. Modify Request (The Exploit):**
- **Method:** Change `POST` to `GET`.
- **Cookie:** Replace `ADMIN_SESSION_TOKEN` with `WIENER_SESSION_TOKEN`.
- **Payload:** Move parameters to URL and set target user to `wiener`.
```HTTP
GET /admin-roles?username=wiener&action=upgrade HTTP/1.1
Host: <LAB-ID>.web-security-academy.net
Cookie: session=WIENER_SESSION_TOKEN
```

---
## IMPACT
**Critical:** Unauthorized Privilege Escalation. Any authenticated user can bypass the method-based filter to execute administrative actions, such as granting themselves full admin rights.

---
## FIX / MITIGATION
1. **Method-Agnostic Filtering:** Apply access control checks to the endpoint (`/admin-roles`) regardless of the HTTP method.
2. **Strict Method Allowance:** Explicitly reject unexpected methods (e.g., `GET`) with `405 Method Not Allowed`.
3. **Framework Hardening:** Configure the web framework to disable automatic parameter mapping from query strings for state-changing actions.

---
## KEY LEARNING
**Test Access, Not Just UI.** Just because the UI uses `POST` doesn't mean the backend rejects `GET`. Always test access control by taking a privileged request and swapping the session cookie with a low-privileged one, then iterating through HTTP methods (`GET`, `POST`, `PUT`, `HEAD`) to find bypasses.

---
