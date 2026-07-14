# Exploiting NoSQL Injection to Extract Data
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Exploiting NoSQL Injection to Extract Data_

---
## DESCRIPTION
The user lookup functionality allows users to search for other users by username. The backend is powered by a **MongoDB** database. The application is vulnerable to NoSQL injection because it concatenates the username input into a JavaScript expression executed by the `$where` operator (or similar JavaScript evaluation context within MongoDB).

---
## ROOT CAUSE
**JavaScript Injection in Query (where):** The application likely constructs a query similar to: `this.username == '$user\_input'`Because the input is not sanitized, an attacker can break out of the string comparison using a single quote`'\` and inject arbitrary JavaScript logic that the database executes.

---
## ATTACK SCENARIO
1. **Detection:** Injecting `administrator' && 1==1 || 'a'=='b` returns the administrator's profile (True). Injecting `administrator' && 1==0 || 'a'=='b` returns nothing (False). This confirms **Boolean Injection**.
2. **Length Enumeration:** The attacker iterates through integers `N`, injecting `this.password.length > N`. When the server stops returning the profile, the exact length is found.
3. **Data Extraction:** The attacker iterates through every character of the password field using array indexing (`this.password[i]`).
    - _Query:_ `administrator' && this.password[0] == 'a' || 'a'=='b`
    - If the server returns the profile, the first character is 'a'.
4. **Login:** The extracted password is used to authenticate as the administrator.
---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/user/lookup`
- **Parameter:** `user`
- **Method:** GET
### Payload Used
```javascript
administrator' && this.password[0] == 'a' || 'a' == 'b
```
(URL Encoded automatically by browser/script)
### Retrieval Point
The presence or absence of the "administrator" user details in the HTTP response body serves as the True/False oracle.

---
## IMPACT
**Critical (Data Exfiltration / Account Takeover):** The vulnerability allows an attacker to extract any field from the user document (passwords, emails, tokens) character-by-character, leading to full account takeover of any user, including administrators.

---
## FIX / MITIGATION
1. **Avoid `$where`:** The `$where` operator is slow and insecure. Use standard MongoDB query operators (like `$eq`, `$gt`) whenever possible.
2. **Sanitization:** If JavaScript execution is required, strictly validate that user input does not contain quote characters or JavaScript syntax.
3. **Permissions:** Disable server-side scripting in MongoDB configuration (`security.javascriptEnabled: false`) if the application does not strictly require it.
---
## KEY LEARNING
- **The `this` Context:** In MongoDB JavaScript queries (`$where`, `mapReduce`), the keyword `this` refers to the current document being processed. You can access hidden fields like `this.password` even if the application never displays them.
- **JavaScript Syntax:** Since the injection happens inside a JS engine, you can use standard JS properties like `.length`, `.match()`, or array indexing `[i]`.
---
