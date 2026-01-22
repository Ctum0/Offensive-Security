# SQL injection UNION attack, finding a column containing text
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection UNION attack, finding a column containing text_

---
## DESCRIPTION
The application is vulnerable to SQL injection in the product category filter.  
Query results are returned in the response, allowing a UNION-based SQL injection to be used.

---
## ROOT CAUSE
User input from the `category` parameter is directly concatenated into a SQL query.  
The application does not use prepared statements and reflects query results.

---
## ATTACK SCENARIO
1. The user filters products by category.
2. The backend executes a query similar to:
```SQL
SELECT name, description, price FROM products WHERE category = 'Gifts'
```
3. The attacker injects a UNION SELECT statement to match the column count:
```SQL
'UNION SELECT NULL,NULL,NULL--
```
3. After confirming three columns, the attacker replaces each `NULL` with a string value.
4. When the string value appears in the response, the attacker identifies a column compatible with text data.

---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: String
### Payload Used
`'UNION SELECT NULL,'abcdef',NULL--`
### Result
The string value appears in the response, confirming that the second column accepts string data.

---
## IMPACT
An attacker can identify which columns support string data.  
This allows further UNION-based SQL injection to extract sensitive information.

---
## FIX / MITIGATION
- Use prepared statements / parameterized queries
- Avoid dynamic SQL construction using user input
- Do not return raw database results to users
---
## KEY LEARNING
- UNION attacks require correct column count and data types
- Testing string compatibility is required before data extraction
- Reflected query results increase exploitation severity

---
