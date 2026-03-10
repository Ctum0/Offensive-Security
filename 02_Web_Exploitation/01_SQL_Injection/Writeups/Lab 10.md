# SQL injection UNION attack, retrieving multiple values in a single column
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, retrieving multiple values in a single column_

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
3. The attacker confirms the query returns two columns, but only one column accepts text:
```SQL
' UNION SELECT NULL,'abc'--
```
4. Because only one column supports text, the attacker **combines multiple values into one column**.
5. The attacker retrieves usernames and passwords by concatenating them:
```SQL
' UNION SELECT NULL, username || '~' || password FROM users--
```
6. The response displays usernames and passwords in a single column.
7. The attacker logs in as the administrator using the extracted credentials.

---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String
### Payload Used
`' UNION SELECT NULL, username || '~' || password FROM users--`
### Result
The response contains concatenated usernames and passwords, separated by `~`.

---
## IMPACT
An attacker can extract credentials even when only one text column is available.  
This leads to full account compromise.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Avoid dynamic SQL query construction
- Do not return database query results

---
## KEY LEARNING
- UNION attacks require matching column count and data types
- If only one text column exists, values must be concatenated
- The `||` operator combines multiple values into one column
- Credential extraction enables account takeover

---
