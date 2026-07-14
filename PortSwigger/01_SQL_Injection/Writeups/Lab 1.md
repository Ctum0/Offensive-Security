# SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
---
## TARGET
PortSwigger Web Security Academy  
Lab: _SQL injection vulnerability in WHERE clause allowing retrieval of hidden data_

---
## DESCRIPTION
The application is vulnerable to SQL Injection in the product category filter.  
User-supplied input is directly embedded into a SQL query without proper parameterization, allowing an attacker to manipulate the query logic and bypass intended restrictions.

----
## ROOT CAUSE
The application constructs SQL queries by concatenating user input directly into the WHERE clause instead of using prepared statements.
Because the input is not safely handled, injected SQL logic becomes part of the executed query.

---
## ATTACK SCENARIO
1. The user selects a product category.
2. The application sends a request containing the selected category as a parameter.
3. The backend uses this value directly in a SQL query:
```sql
SELECT * FROM products  WHERE category = 'Gifts' AND released = 1;
```
4. An attacker modifies the category parameter to inject SQL logic.
5. The injected logic alters the WHERE clause, causing the application to return unreleased products.

---
## PROOF OF CONCEPT
### Injection Point
- Parameter: `category`
- Context: STRING
### Payload Used
`' OR 1=1--`
### Result
The injected condition `OR 1=1` always evaluates to TRUE, and the comment `--` removes the `released = 1` restriction.
As a result, the application returns **all products**, including unreleased items that should not be visible to users.

---
## IMPACT
An attacker can bypass application logic and access hidden or restricted data.  
In a real-world scenario, this could expose:
- Unreleased products
- Sensitive internal data
- Business logic not intended for public access

---
## FIX / MITIGATION
- Use **prepared statements / parameterized queries**
- Ensure user input is treated strictly as data, not executable SQL
- Avoid dynamically building SQL queries using string concatenation

---
## KEY LEARNING
- SQL Injection works by **manipulating query logic**.
- The `' OR 1=1--` payload closes the string, forces a TRUE condition, and comments out the rest of the query
- Understanding the SQL query structure makes exploitation straightforward

---
