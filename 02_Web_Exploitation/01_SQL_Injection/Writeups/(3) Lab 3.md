# SQL injection UNION attack, determining the number of columns returned by the query
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, determining the number of columns returned by the query_

---
## DESCRIPTION
The application is vulnerable to SQL injection via the product category filter. Because query results are reflected in the response, a UNION-based SQL injection can be used to manipulate the query and infer its structure.

---
## ROOT CAUSE
User input from the `category` parameter is directly concatenated into a SQL query without parameterization, allowing attackers to inject arbitrary SQL logic.

---
## ATTACK SCENARIO
1. The user filters products by category.
2. The backend executes a query similar to:
```SQL
SELECT name, description, price FROM products WHERE category = 'Gifts'
```
3. An attacker injects a UNION SELECT statement into the `category` parameter:
```SQL
'UNION SELECT NULL--
```
4. The application returns an error because the injected query does not match the number of columns.
5. The attacker adds additional `NULL` values:
```SQL
' UNION SELECT NULL,NULL,NULL--
```
6. When the correct number of columns is supplied, the query executes successfully and the injected row appears in the response.
---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String
### Payload Used
`'+UNION+SELECT+NULL,NULL,NULL--`
### Result
The error disappears and additional content is returned, confirming the number of columns used in the original query.

---
## IMPACT
An attacker can determine the number of columns returned by the SQL query.  
This enables further UNION-based SQL injection attacks to extract sensitive data.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Avoid constructing SQL queries using user input
- Do not expose database error messages

---
## KEY LEARNING
- UNION-based SQL injection requires matching column counts
- Incrementing `NULL` values is a reliable way to identify column structure
- Understanding query structure is critical for further exploitation

---
