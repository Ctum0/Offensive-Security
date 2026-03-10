#  SQL injection vulnerability allowing login bypass
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection vulnerability allowing login bypass_

---
## DESCRIPTION
The application is vulnerable to SQL Injection in the login functionality.  
User input is directly incorporated into a SQL query without proper parameterization, allowing an attacker to manipulate the query logic and bypass authentication.

---
## ROOT CAUSE
The application constructs SQL queries by directly embedding user-supplied input into the WHERE clause.  
Because prepared statements are not used, injected SQL logic becomes part of the executed query.

---
## ATTACK SCENARIO
1. The user navigates to the login page via the **My Account** link.
2. When a username and password are submitted, the backend executes a query similar to:
```SQL
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```
3. An attacker injects SQL logic into the username field using:
```SQL
administrator'--
```
4. The comment sequence (`--`) causes the password condition to be ignored.
5. The application authenticates the attacker as the administrator without requiring a password.
---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `username`
- Context: STRING
### Payload Used
`administrator'--`
### Result
The injected payload comments out the password check (`AND password = '...'`), allowing authentication as the administrator without valid credentials.

---
## IMPACT
An attacker can bypass authentication and gain unauthorized access to user accounts.  
In a real-world application, this could lead to:
- Account takeover
- Exposure of sensitive internal data
- Full administrative access
---
## FIX / MITIGATION
- Use **prepared statements / parameterized queries**
- Treat all user input strictly as data  
- Avoid constructing SQL queries via string concatenation
---
## KEY LEARNING
- Authentication logic is a common target for SQL Injection
- SQL comments (`--`) can be used to remove security checks
- Login bypass does not require data extraction to be severe
- Proper query parameterization completely prevents this attack.
---
