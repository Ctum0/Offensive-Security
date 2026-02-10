# User role can be modified in user profile
---
## TARGET
PortSwigger Web Security Academy  
Lab: _User role can be modified in user profile_
Vulnerability: _Mass Assignment (Broken Access Control)_

---
## DESCRIPTION
The application allows users to update their profile information (specifically, their email address) via a JSON API. The endpoint blindly accepts user-supplied JSON parameters and binds them to the underlying user object without filtering. This allows an attacker to inject sensitive parameters, such as `roleid`, to elevate privileges.

---
## ROOT CAUSE
**Mass Assignment (Auto-Binding):** The application framework automatically binds input parameters (JSON) to internal object fields. The developer failed to explicitly whitelist allowed fields (e.g., only `email`) or blacklist sensitive fields (e.g., `roleid`), allowing attackers to overwrite the user's role.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker logs in and updates their email address while capturing the traffic.
2. **Discovery:** The API response to the email update includes the user's full profile object, revealing a `"roleid": 1` parameter.
3. **Exploitation:** The attacker repeats the update request but appends `"roleid": 2` to the JSON payload.
4. **Verification:** The server processes the request, updating the email and the role ID. The attacker navigates to `/admin` and gains access.
5. **Action:** The attacker deletes the user `carlos`.

---
## PROOF OF CONCEPT
**Original Request:**
```HTTP
POST /my-account/change-email HTTP/1.1
Content-Type: application/json

{
  "email": "attacker@normal-user.net"
}
```
**Exploit Request:**
```HTTP
POST /my-account/change-email HTTP/1.1
Content-Type: application/json

{
  "email": "attacker@admin.net",
  "roleid": 2
}
```

---
## IMPACT
**Critical:** Privilege Escalation. An authenticated low-privileged user can become an administrator, granting full control over the application and its data.

---
## FIX / MITIGATION
1. **Use DTOs (Data Transfer Objects):** Bind input data to a specific object that only contains allowed fields, rather than the raw database entity.
2. **Field Whitelisting:** Explicitly define which parameters can be updated by the user (e.g., `permit(:email)`).
3. **Role Validation:** Never allow users to set their own role ID via client-side input.

---
## KEY LEARNING
**Filter Input, Don't Just Echo It.** Modern frameworks often make it easy to bind JSON to objects. This convenience is a security risk. Always verify what the user is trying to update. Just because a parameter isn't in the form UI doesn't mean an attacker can't send it in the request.

---
