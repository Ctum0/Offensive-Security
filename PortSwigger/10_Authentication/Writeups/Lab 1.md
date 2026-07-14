# Username enumeration via different responses
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Username enumeration via different responses_
Vulnerability: _Authentication Vulnerability (Username Enumeration)_

---
## DESCRIPTION
The applications authentication mechanism contains a critical enumeration vulnerability. By analyzing variation in the servers error responses, an attacker can definitely confirm whether a specific username exists within the database. Once a valid username is isolated, the attacker can shift from blind guessing to executing a highly targeted brute-force attack to extract the correct password and compromise the account.

---
## ROOT CAUSE
The primary deficiency is the implementation of verbose, distinct error messages during the authentication process. The application fails to provide a uniform response for failed logins (e.g., distinguishing between an "Invalid username" and an "Incorrect password). This architectural flaw inadvertently leaks the internal database status of user accounts to unauthenticated actors.

---
## ATTACK SCENARIO
1. Intercepts the authentication request and routes it to an automated fuzzing tool.
2. Injects a payload of potential usernames and analyzes the resulting HTTP responses.
3. Isolates the valid username by observing a unique error message or response length (e.g., the server returns "Incorrect password" instead of "Invalid username").
4. Extracts the correct password and authenticates into the compromised account.

---
## PROOF OF CONCEPT
**Injection Point:** `username` and `password` parameters in the POST `/login` request.
**Enumeration Indicator:** The server responds with different HTML string lengths and error messages depending on the validity of the username.
**Execution Method:** Automated payload delivery utilizing Burp Suite Intruder (Sniper attack for the username, followed by a Sniper attack for the password).

---
## IMPACT
This vulnerability facilitates targeted brute-force attacks by verifying targets for the attacker. This directly leads to complete account takeover and unauthorized access to sensitive user data.

---
## FIX / MITIGATION
Implement generic, **uniform** error messages for all failed login attempts (e.g., "Invalid username or password"). Ensure that both the HTTP response time and the response length remain identical regardless of whether the account exists. Additionally, implement rate limiting and account lockout mechanisms to prevent brute-force attempts.

---
## KEY LEARNING
Authentication workflows must never leak the validity of an account. Always enforce generic, uniform error handling to neutralize enumeration tactics.

---
