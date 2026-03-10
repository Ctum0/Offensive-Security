# Authentication bypass via flawed state machine
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Authentication bypass via flawed state machine_
Vulnerability: _Broken Access Control (Flawed State Machine / Privilege Escalation)_

---
## DESCRIPTION
The application utilizes a flawed finite-state machine during its authentication workflow. It assumes the user will blindly follow the chronological sequence of HTTP redirects. By interrupting this sequence—specifically by dropping the redirect issued immediately after credential submission—an attacker can bypass the role-assignment phase and retain a default, elevated session state.

---
## ROOT CAUSE
**Insecure Default State and Client-Driven Transitions:** The backend temporarily elevates the user's session privileges upon initial credential verification, expecting the client to follow a `302 Found` redirect to a subsequent endpoint (like a role-selector) where standard privileges are finally enforced. If the client refuses to follow the redirect, the state machine halts prematurely, leaving the session permanently stuck in the elevated administrative state.

---
## ATTACK SCENARIO
1. **Initialization:** The attacker navigates to the login page and captures the CSRF token.
2. **Authentication Submission:** The attacker submits valid standard credentials (`wiener:peter`).
3. **State Machine Interruption:** The server verifies the credentials, issues a privileged session cookie, and commands a redirect. The attacker drops the redirect.
4. **Execution:** Operating with the fully privileged session cookie, the attacker bypasses the intended workflow, navigates directly to the `/admin` panel, and executes the deletion of the target user.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /login` (Intercepting and dropping the subsequent response) **Payload:** Submit valid credentials and block the `302` redirect.
**Retrieval:** Navigate directly to `GET /admin/delete?username=carlos`.

---
## IMPACT
**Critical:** Unauthorized Privilege Escalation. Any authenticated user can trivially bypass role-based access controls to achieve full administrative control over the application.

---
## FIX / MITIGATION
1. **Default to Least Privilege:** Sessions must be initialized with the lowest possible privilege level (or a strict "pending" state).
2. **Server-Side State Enforcement:** Only elevate privileges _after_ all phases of the authentication and role-verification workflow are successfully completed and cryptographically verified on the backend. Never rely on the client to complete a workflow sequence.

---
## KEY LEARNING
**Never trust the client to advance the state machine.** If an application requires a multi-step workflow, the server must enforce the sequence and never grant sensitive access until the final stage is verifiably complete.

---
