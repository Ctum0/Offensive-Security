# SQL injection UNION attack, retrieving data from other tables

---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, retrieving data from other tables_

---
## DESCRIPTION
The application is vulnerable to SQL injection in the product category filter.  
Query results are returned in the response, allowing a UNION-based SQL injection to retrieve data from other tables.

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
3. The attacker injects a UNION SELECT statement with matching columns:
```SQL
' UNION SELECT 'abc','def'--
```
3. The response confirms two columns, both accepting text data.
4. The attacker retrieves data from the `users` table:
5. Usernames and passwords appear in the response.
```SQL
' UNION SELECT username, password FROM users--
```
3. The attacker logs in as the administrator using the extracted credentials.
---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String
### Payload Used
`' UNION SELECT username, password FROM users--`
### Result
The response contains usernames and passwords, allowing authentication as the administrator.

---
## IMPACT
An attacker can extract sensitive credentials from the database.  
This can lead to full account takeover and administrative access.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Prevent dynamic SQL construction with user input
- Do not return raw database query results
---
## KEY LEARNING
- UNION attacks can extract data from other tables
- Column count and data type matching are required
- Reflected query results make data exfiltration possible

---
