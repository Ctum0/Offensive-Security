# Inconsistent handling of exceptional input
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Inconsistent handling of exceptional input_
Vulnerability: _Business Logic Flaw (Database String Truncation)_

---
## DESCRIPTION
The application exhibits a desynchronization flaw between its email dispatch system and its backend database. The email dispatcher processes extremely long email strings without length validation, while the database strictly truncates the email field to 255 characters upon saving the user profile. This inconsistency allows an attacker to register a spoofed administrative email address that routes the confirmation link to an attacker-controlled server.

---
## ROOT CAUSE
**Inconsistent Input Validation:** The system fails to enforce uniform data constraints across all microservices/components. The database enforces a `VARCHAR(255)` limit, silently dropping excess characters instead of throwing an error. The application logic trusts the truncated database value for role-based access control rather than the original input.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker identifies that users with an `@dontwannacry.com` email address receive administrative privileges.
2. **Payload Crafting:** The attacker generates an email string exactly 238 characters long, followed by `@dontwannacry.com.`, appending their own exploit server domain at the end. The `m` in `.com` sits exactly at the 255th character.
3. **Registration:** The attacker registers with this payload.
4. **Routing:** The email dispatcher reads the full string and correctly routes the confirmation email to the attacker's exploit server subdomain.
5. **Truncation:** The database saves the user profile but truncates the string at 255 characters, stripping the exploit server domain and leaving the user's registered email as `[238 characters]@dontwannacry.com`.
6. **Execution:** The attacker clicks the confirmation link, logs in, and utilizes their newly granted administrative privileges to delete the target user.

---
## PROOF OF CONCEPT
**Injection Point:** `POST /register` (Email Field)
**Payload:**
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@dontwannacry.com.exploit-<ID>.exploit-server.net
```
**Retrieval:** Check the exploit server email client for the `temp-registration-token` link.

---
## IMPACT
**Critical:** Unauthorized Privilege Escalation. The attacker gains full administrative control over the application, allowing for data destruction and account manipulation.

---
## FIX / MITIGATION
1. **Strict Input Validation:** Enforce strict length limits (e.g., maximum 255 characters) at the application tier _before_ the data reaches the database or external services. Reject the input entirely if it exceeds the limit.
2. **Uniform Constraints:** Ensure all components (email dispatchers, authentication services, databases) adhere to the exact same data validation rules.

---
## KEY LEARNING
**Silent Truncation is Dangerous.** Never allow a database to silently truncate data to fit a column limit. If input exceeds the schema limits, the application must throw an error and halt the transaction.

---
