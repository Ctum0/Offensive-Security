# User ID controlled by request parameter with password disclosure
---
## TARGET
PortSwigger Web Security Academy  
Lab: _User ID controlled by request parameter with password disclosure_
Vulnerability: _Broken Access Control (IDOR combined with Information Disclosure)_

---
## DESCRIPTION
The application contains a "My Account" page that displays the user's profile information. Uniquely, it pre-fills the password field with the user's current password (masked as dots). The application fails to verify if the user is authorized to view the requested profile ID. By modifying the `id` parameter, an attacker can load the administrator's profile and extract their password from the HTML source.

---
## ROOT CAUSE
**Insecure Direct Object Reference (IDOR) & Unsafe Design:**
1. **IDOR:** The server blindly trusts the `id` parameter (e.g., `id=administrator`) without validating that it matches the currently authenticated session.
2. **Password Disclosure:** The application populates the `<input type="password">` field with the actual plaintext password in the `value` attribute, relying on the browser's UI masking for security.

---
## ATTACK SCENARIO
1. **Login:** The attacker logs in as a low-privileged user (`wiener`).
2. **Tampering:** The attacker navigates to the account page and modifies the URL parameter to `id=administrator`.
3. **Extraction:** The server renders the administrator's account page. The attacker inspects the page source and finds the admin password in the HTML: `<input name="password" value="ADMIN_PASSWORD">`.
4. **Privilege Escalation:** The attacker logs out, then logs back in using the username `administrator` and the extracted password.
5. **Action:** The attacker uses their new administrative access to delete the user `carlos`.

---
## PROOF OF CONCEPT
**Vulnerable Request:**
```HTTP
GET /my-account?id=administrator HTTP/1.1
Cookie: session=WIENER_SESSION_TOKEN
```
**Response (HTML Source):**
```HTTP
<label>Password</label>
<input required type="password" name="password" value="s3cret_admin_p@ss">
```

---
## IMPACT
**Critical:** Complete Account Takeover. The vulnerability allows any authenticated user to steal the password of any other user, including administrators, leading to full system compromise.

---
## FIX / MITIGATION
1. **Never Pre-fill Passwords:** Password fields should always be empty on profile update pages. Users should only enter a password if they intend to change it.
2. **Authorization Checks:** Validate that the `id` requested matches the session owner's ID.

---
## KEY LEARNING
**Masking ≠ Encryption.** The dots you see in a password field are just a UI feature of the browser. If the `value` attribute is set in the HTML, the plaintext password is sitting in the browser's memory and source code, fully accessible to anyone who can view the page.

---
