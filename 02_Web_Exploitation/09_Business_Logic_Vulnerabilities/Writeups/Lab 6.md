# Inconsistent security controls
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Inconsistent security controls_
Vulnerability: _Business Logic Flaw (Inconsistent Validation)_

---
## DESCRIPTION
The application enforces strict security controls during user registration by requiring email verification. However, it fails to apply the same level of validation when a user updates their email address from their profile page. This inconsistency allows an attacker to register with an attacker-controlled email, verify the account, and then arbitrarily change their profile email to a privileged domain (`@dontwannacry.com`) without subsequent verification, instantly escalating their privileges.

---
## ROOT CAUSE
**Inconsistent Security Enforcement:** The development team applied a security control (email ownership verification) to one entry point (Registration) but neglected to apply the exact same control to another entry point (Profile Update) that modifies the same sensitive database field. The application's role-based access control (RBAC) blindly trusts the database's `email` value without verifying its origin state.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker observes that administrative access is granted to users with `@dontwannacry.com` email addresses.
2. **Initial Access:** The attacker registers a standard account using an email address they control and clicks the confirmation link to fully activate the session.
3. **Exploitation:** The attacker navigates to their profile settings and updates their email address to `attacker@dontwannacry.com`.
4. **Bypass:** The application updates the database record without sending a new confirmation email to the `@dontwannacry.com` address.
5. **Execution:** The attacker's session is now associated with the privileged domain. They access the `/admin` panel and delete the target user.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /my-account/change-email`
**Payload:**
```HTTP
email=attacker@dontwannacry.com&csrf=[TOKEN]
```

---
## IMPACT
**Critical:** Unauthorized Privilege Escalation. An attacker bypasses the core authentication requirement to gain administrative control over the application.

---
## FIX / MITIGATION
1. **Consistent State Validation:** Apply the same verification workflow to email updates as is applied to new registrations.
2. **Pending State Lock:** If a user changes their email, their account should be temporarily demoted or the new email placed in a "pending" state until a verification link sent to the _new_ address is clicked.

---
## KEY LEARNING
**Security must be uniform.** A chain is only as strong as its weakest link. If a sensitive attribute (like an email address used for authorization) can be modified through multiple pathways, every single pathway must enforce identical validation checks.

---
