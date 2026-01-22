# Visible error-based SQL injection
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Visible error-based SQL injection_

---
## DESCRIPTION
The application uses a tracking cookie for analytics. The application is vulnerable to SQL Injection. Unlike "Blind" scenarios, this application is **verbose**: if the SQL query fails, the application returns the full database error message in the HTTP response.

---
## ROOT CAUSE
The `TrackingId` cookie is unsanitized and directly concatenated into a SQL query. Furthermore, the application configuration has "Verbose Error Messages" enabled, which reflects database internal states (and data) back to the user when a syntax or logic error occurs.

---
## ATTACK SCENARIO
1. **Injection Verification:** The attacker adds a single quote `'` to the `TrackingId`. The server responds with `Unterminated string literal...`, confirming a **PostgreSQL** database and visible errors.
2. **Constraint Discovery:** The attacker attempts to extract the password using `CAST((SELECT password...) AS INT)`. The error message shows the query was cut off (`...LIMIT'`), revealing a strict **Character Limit** on the cookie input.
3. **Bypass:** The attacker removes the original valid `TrackingId` value to free up space for the payload.
4. **Data Extraction (The "Cast" Trick):** The attacker injects a payload that forces the database to convert the password string into an integer.
    - Query: "Please treat the password 's3cr3t' as a Number."
    - Result: The database crashes and prints: `invalid input syntax for type integer: "s3cr3t"`.

---
## PROOF OF CONCEPT
### Injection Point
- **Header:** `Cookie: TrackingId=...`
- **Context:** PostgreSQL (Verbose)

### Payload Used
```SQL
' AND CAST((SELECT password FROM users LIMIT 1) AS INT)=1--
```
### Result
The Server returns HTTP 500 with the error message:
`ERROR: invalid input syntax for type integer: "h78ad..."`

---
## IMPACT
High. An attacker can extract the entire database contents (passwords, user data, schema) request-by-request by simply triggering type conversion errors, without needing to brute-force character by character.

---
## FIX / MITIGATION
- **Disable Verbose Errors:** Configure the web server and database to return generic error messages (e.g., "An error occurred") to the user.
- **Parameterized Queries:** Use Prepared Statements to prevent the injection entirely.
- **Input Validation:** Enforce strict allow-lists for cookie formats (e.g., alphanumeric only).

---
## KEY LEARNING
- **Visible Errors are Critical:** If an app leaks error messages, we don't need "Blind" techniques. We can use `CAST(... AS INT)` to dump data instantly.
- **Character Limits:** Sometimes a payload fails not because of syntax, but because it was truncated. Checking the error message carefully (e.g., seeing where the query stopped) can reveal hidden length constraints.
- **Optimization:** Deleting the original parameter value is a simple way to gain extra space for a payload.

---
