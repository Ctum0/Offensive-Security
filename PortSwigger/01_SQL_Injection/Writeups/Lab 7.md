# SQL injection UNION attack, querying the database type and version (MySQL / Microsoft)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, querying the database type and version (MySQL / Microsoft)_

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
' UNION SELECT 'abc','def'#
```
4. The attacker identifies the database as **MySQL or Microsoft SQL Server**.
5. The attacker retrieves the database version using:
```SQL
' UNION SELECT @@version, NULL#
```
6. The database version string appears in the response.
---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String
### Payload Used
`' UNION SELECT @@version, NULL#`
### Result
The response displays the database version string.

---
## IMPACT
An attacker can identify the database type and version.  
This information enables database-specific exploitation.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Avoid dynamic SQL construction using user input
- Do not expose database query results

---
## KEY LEARNING
- Database-specific syntax matters in SQL injection
- MySQL and Microsoft SQL Server support `@@version`
- `#` can be used as a comment instead of `--`
- UNION attacks can retrieve database metadata

---
