# SQL injection UNION attack, retrieving the database version (Oracle)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, retrieving the database version (Oracle)_

---
## DESCRIPTION
The application is vulnerable to SQL injection in the product category filter.  
Query results are returned in the response, allowing a UNION-based SQL injection to retrieve database information.

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
3. The attacker confirms the query returns two text columns using:
```SQL
' UNION SELECT 'abc','def' FROM dual--
```
4. The attacker identifies the database as **Oracle**.
5. The attacker retrieves the database version using:
```SQL
' UNION SELECT BANNER, NULL FROM v$version--
```
6. The database version string appears in the response.

---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String
### Payload Used
`' UNION SELECT BANNER, NULL FROM v$version--`
### Result
The response displays the Oracle database version string.

---
## IMPACT
An attacker can identify database version and platform details.  
This information can be used to craft database-specific attacks.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Prevent dynamic SQL query construction
- Avoid returning database query results to users
---
## KEY LEARNING
- Database-specific syntax matters in SQL injection
- Oracle requires `FROM dual` for SELECT statements
- Oracle version information is stored in `v$version`
- UNION attacks can retrieve internal database metadata

---
