# Exploiting NoSQL Operator Injection to Bypass Authentication
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Exploiting NoSQL Operator Injection to Bypass Authentication_

---
## DESCRIPTION
The login mechanism is powered by a **MongoDB** NoSQL database. The application accepts credentials in JSON format (even if the default form uses URL-encoding). It fails to validate that the input values are simple strings. This allows an attacker to supply a JSON Object containing NoSQL query operators.

---
## ROOT CAUSE
**Insecure Input Handling (Object Injection):** The application blindly parses the JSON body and passes it to the database query.
- _Vulnerable Pattern:_ `db.users.findOne({username: req.body.username, password: req.body.password})`
- _Exploit:_ By sending an object `{"$ne": ""}` instead of a string, the query logic changes from equality (`==`) to inequality (`!=`).
---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker identifies that the login endpoint accepts JSON input (by changing `Content-Type: application/json`).
2. **Payload Construction:**
    - **Username:** Uses `{"$regex": "admin.*"}` to match the administrator account even if the exact username is unknown.
    - **Password:** Uses `{"$ne": ""}` to assert that the password is "not empty".
3. **Execution:** The query becomes `Find user where username matches 'admin.*' AND password is NOT empty`.
4. **Result:** Since the admin password exists (is not empty), the condition evaluates to **True**, and the database returns the admin session.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/login`
- **Headers:** `Content-Type: application/json`
- **Method:** POST
### Payload Used
```json
{
    "username": {"$regex": "admin.*"},
    "password": {"$ne": ""}
}
```
### Retrieval Point
The server responds with a `302 Found` redirect (Location: `/my-account`), confirming a valid session creation.

---
## IMPACT
**Critical (Authentication Bypass):** The attacker gains administrative access to the application without any valid credentials, leading to full account takeover.

---
## FIX / MITIGATION
1. **Type Validation:** Ensure `username` and `password` are strictly Strings before processing.
2. **Sanitization:** Strip keys starting with `$` from user input to prevent operator injection.
3. **Input Schema:** Use a strict schema (like Mongoose) that rejects unexpected object structures.

---
## KEY LEARNING
**JSON Content Switching:** Always test login forms by switching the `Content-Type` to `application/json`. Many modern frameworks automatically parse JSON bodies, opening the door to NoSQL operator injection that isn't possible with standard form data.

---
