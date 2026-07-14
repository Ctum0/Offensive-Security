# User role controlled by request parameter
---
## TARGET
PortSwigger Web Security Academy  
Lab: _User role controlled by request parameter_
Vulnerability: _Broken Access Control (Privilege Escalation via Cookie Tampering)_

---
## DESCRIPTION
The application hosts an administrative panel at `/admin`. The authentication mechanism relies on a non-secure cookie (`Admin=false`) to determine the user's role. This cookie is susceptible to client-side modification, allowing a standard user to elevate their privileges to an administrator simply by changing the boolean value.

---
## ROOT CAUSE
**nsecure Authorization Model:** The application uses a client-side cookie as the sole source of truth for user privileges. It fails to validate the user's role against a secure server-side session or database, allowing users to arbitrarily define their own permissions.

---
## ATTACK SCENARIO
1. **Login:** The attacker logs in with valid credentials (`wiener:peter`).
2. **Interception:** Using a proxy tool (Burp Suite) or Browser DevTools, the attacker inspects the HTTP response headers and identifies a cookie named `Admin` set to `false`.
3. **Tampering:** The attacker modifies the cookie value to `true` in the browser storage or intercepts the next request and changes the header to `Cookie: Admin=true`.
4. **Access:** The attacker navigates to `/admin`, bypassing the restriction.
5. **Exploitation:** The attacker clicks the "Delete" button for user `carlos`.

---
## PROOF OF CONCEPT
**Manual Exploit Steps:**
1. Log in as `wiener` with password `peter`.
2. Open Developer Tools (F12) -> **Application** (Chrome) or **Storage** (Firefox) -> **Cookies**.
3. Find the `Admin` cookie.
4. Double-click the value `false` and change it to `true`.
5. Refresh the page and navigate to `/admin`.
6. Delete user `carlos`.

**HTTP Request (Tampered):**
```HTTP
GET /admin/delete?username=carlos HTTP/1.1
Host: <LAB-ID>.web-security-academy.net
Cookie: session=...; Admin=true
```

---
## IMPACT
**Critical:** Unauthorized Privilege Escalation. Any authenticated user can become an administrator, leading to complete system compromise and data loss.

---
## FIX / MITIGATION
1. **Server-Side Sessions:** Store user roles in a secure, server-side session. The client should only hold a session ID, not privilege details.
2. **Integrity Checks:** If client-side tokens are necessary (e.g., JWT), ensure they are cryptographically signed to prevent tampering.

---
## KEY LEARNING
**Never Trust the Client.** Cookies are user-controlled input. Any data stored in a cookie that controls logic (like `isAdmin`, `role`, `price`) can and will be modified by attackers. Always validate privileges on the server.

---
