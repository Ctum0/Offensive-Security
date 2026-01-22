# Blind SQL injection with time delays and information retrieval
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Blind SQL injection with time delays and information retrieval_

---
## DESCRIPTION
The application uses a tracking cookie for analytics. The application is vulnerable to Blind SQL Injection. It is "Fully Blind" (no error messages, no content changes). The database executes queries synchronously. The goal is to extract the administrator's password and log in.

---
## ROOT CAUSE
The `TrackingId` cookie is used in a SQL query without sanitization. The synchronous nature of the database allows an attacker to inject conditional time delays (e.g., `pg_sleep`) to infer data bit-by-bit.

---
## ATTACK SCENARIO
1. **Fingerprinting:** The attacker identifies the database as PostgreSQL by confirming that `' || pg_sleep(10)--` causes a delay.
2. **Boolean-to-Time Conversion:** The attacker constructs a payload that converts a Boolean question (True/False) into a Time event (Sleep/No Sleep).
    - Logic: `IF (condition) THEN sleep(10) ELSE sleep(0)`
3. **Data Extraction:**
    - **Length:** "If password length > 1, sleep." -> (Sleeps) -> True.
    - **Content:** "If 1st char is 'a', sleep." -> (Instant) -> False. "If 1st char is 'x', sleep." -> (Sleeps) -> True.
4. **Login:** The attacker uses the extracted password to log in as administrator.

---
## PROOF OF CONCEPT
### Injection Point
- **Header:** `Cookie: TrackingId=...`
- **Context:** PostgreSQL (Time-Based)

### Payload Used(Conditional)
Note: This asks "Is the first letter 'x'?"
```SQL
' || (SELECT CASE WHEN (SUBSTR(password,1,1)='x') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator') --
```
### Result
- **Condition True:** Server responds after **10+ seconds**.
- **Condition False:** Server responds immediately (**< 1 second**).
---
## IMPACT
High. Despite the lack of visual feedback, an attacker can extract sensitive data (passwords, PII) with 100% accuracy, provided they have enough time to run the automated attack.

---
## FIX / MITIGATION
- **Parameterized Queries:** The primary defense.
- **Asynchronous Logging:** Decouple the analytics logging from the user response.
- **WAF (Web Application Firewall):** Detect and block keywords like `pg_sleep`, `WAITFOR`, or `BENCHMARK`.
---
## KEY LEARNING
- **Patience is Key:** Time-based injection is the slowest extraction method.
- **CASE Statements:** In PostgreSQL, we can't just say `IF` inside a `SELECT`. We use `CASE WHEN ... THEN ... ELSE ... END`.
- **Optimization:** In a real attack, we might use Binary Search (is char > 'm'?) instead of linear search to reduce the number of queries.

---
