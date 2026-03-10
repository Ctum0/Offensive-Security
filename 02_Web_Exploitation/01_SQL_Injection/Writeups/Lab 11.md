# Blind SQL injection with conditional responses
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Blind SQL injection with conditional errors_

---
## DESCRIPTION
The application uses a tracking cookie for analytics. The value of this cookie is used directly in a SQL query. The application is vulnerable to Blind SQL Injection because it does not return data or errors, but it displays a "Welcome back" message differently depending on whether the query returns TRUE or FALSE.

---
## ROOT CAUSE
The `TrackingId` cookie value is concatenated directly into the backend SQL query without sanitization or parameterization. Likely Query: `SELECT * FROM tracking WHERE id = 'COOKIE_VALUE'`

---
## ATTACK SCENARIO
1. The attacker intercepts a request and identifies the `TrackingId` cookie.
2. **Boolean Verification (True):** The attacker appends `' AND '1'='1` to the cookie.
    - Result: The page displays "Welcome back". (Query is TRUE).    
3. **Boolean Verification (False):** The attacker appends `' AND '1'='2` to the cookie.
    - Result: The "Welcome back" message disappears. (Query is FALSE). 
4. **Table Verification:** The attacker confirms the `users` table exists and the administrator is present: Payload: `TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' LIMIT 1)='a`
    - Result: "Welcome back" appears.    
5. **Data Extraction (Limitation):** To get the password, the attacker must ask a Yes/No question for every single character (e.g., "Is the first letter 'a'?"). Doing this manually for a 20-character password would require hundreds of requests, which is feasible but extremely tedious without automation.

---
## PROOF OF CONCEPT
### Injection Point
- **Header:** `Cookie: TrackingId=...`
- **Context:** String / Boolean Logic
### Payloads Used
- **True:** `' AND '1'='1 --`
- **False:** `' AND '1'='2 --`
- **Password Check:** `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a' --`
### Result
The presence or absence of the "Welcome back" string confirms the validity of the injected SQL condition.

---
## IMPACT
An attacker can brute-force sensitive data (like administrator passwords) character by character, leading to full account compromise.

---
## FIX / MITIGATION
- Use **Parameterized Queries** (Prepared Statements) for all database interaction, including cookies.
- Validate that the cookie format matches the expected UUID format before processing.

---
## KEY LEARNING
- **Blind SQLi** occurs when the application does not return database errors or data, but responds differently to True/False queries.
- We act as an "Oracle," asking Yes/No questions to infer data character by character.
- **Automation is essential:** Extracting data this way requires thousands of requests (Length * Character Set size), making manual exploitation impractical.

---
