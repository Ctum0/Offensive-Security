# Blind SQL injection with time delays
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Blind SQL injection with time delays_

---
## DESCRIPTION
The application uses a tracking cookie for analytics. The application is vulnerable to Blind SQL Injection. Unlike previous labs, the application is completely **silent**: it does not return different content (Boolean-based) and does not return different error codes (Error-based) regardless of the query result. However, because the database executes queries synchronously, an attacker can inject time-delay commands to infer information.

---
## ROOT CAUSE
The `TrackingId` cookie is used in a SQL query without sanitization. The application performs the database query synchronously before sending the HTTP response. This allows an attacker to inject database-specific "sleep" commands, causing the server to pause before responding.

---
## ATTACK SCENARIO
1. **Vulnerability Detection (The Silence):** The attacker attempts standard boolean and error-based payloads. The application returns HTTP 200 OK with the same content every time, indicating a "Fully Blind" scenario.
2. **Database Fingerprinting (The Stopwatch):** The attacker "sprays" time-delay payloads for various database types (MySQL, SQL Server, Oracle, PostgreSQL).
3. **Confirmation:**
    - Payload: `TrackingId=x'||pg_sleep(10)--`
    - Result: The request hangs for exactly 10 seconds before returning HTTP 200.
    - Conclusion: The database is **PostgreSQL**, and it is vulnerable to time-based injection.

---
## PROOF OF CONCEPT
### Injection Point
- **Header:** `Cookie: TrackingId=...`
- **Context:** PostgreSQL (Time-Based)
### Payload Used(PostgreSQL)
```SQL
' || pg_sleep(10) --
```
### Result
- **Normal Request:** ~100ms response time.
- **Injected Request:** ~10,100ms response time.

---
## IMPACT
- **Data Extraction:** An attacker can extract sensitive data byte-by-byte (though very slowly) by asking True/False questions: "If the first letter of the password is 'a', sleep for 10 seconds."
- **Denial of Service (DoS):** An attacker could inject a massive sleep time (e.g., `pg_sleep(1000)`), tying up database connections and potentially crashing the server.

---
## FIX / MITIGATION
- **Parameterized Queries:** Prevent the injection entirely by separating code from data.
- **Asynchronous Processing:** Move analytics processing to a background job so the user receives an immediate response regardless of database performance.
- **Input Validation:** Enforce strict allow-lists for cookie formats.

---
## KEY LEARNING
- **The "Stopwatch" Method:** When an application is silent (no content changes, no errors), **Time** is the only remaining side channel.
- **Synchronous vs. Asynchronous:** Time-based injection only works if the server waits for the DB query to finish before sending the HTTP response.
- **Payload Spraying:** Since we get no error messages to tell us the DB type, we must blindly try sleep commands for every major database (PostgreSQL `pg_sleep`, MySQL `SLEEP`, Oracle `dbms_pipe`, MSSQL `WAITFOR DELAY`) until one sticks.

---
