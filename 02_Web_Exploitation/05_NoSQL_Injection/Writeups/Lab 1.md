# Detecting NoSQL Injection
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Detecting NoSQL Injection_

---
## DESCRIPTION
The application uses a **MongoDB** NoSQL database to store product information. The product filter functionality (`/filter?category=...`) is vulnerable to syntax injection. The application likely constructs the database query by concatenating user input directly into a JavaScript expression (e.g., using `$where` or similar evaluation logic).

---
## ROOT CAUSE
**Unsanitized Input in JavaScript Expression:** The application fails to sanitize the `category` parameter before using it in a query context. It likely builds a query string similar to: `this.category == '$user_input'` This allows an attacker to break out of the string literal using a single quote `'` and inject arbitrary boolean logic.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker observes the URL structure `/filter?category=Gifts`.
2. **Fuzzing:** Injecting a single quote `Gifts'` causes a server error or a blank page, indicating a syntax break. Injecting `Gifts\'` (escaped quote) restores normal functionality, confirming the injection point.
3. **Exploitation:** The attacker injects a Boolean OR condition that is always true: `'||'1'=='1`
    - _Original Query:_ `this.category == 'Gifts'`
    - _Injected Query:_ `this.category == 'Gifts'||'1'=='1'`
4. **Result:** Since `'1'=='1'` is always true, the database returns every document in the collection, ignoring the category restriction and the "released" flag.
---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/filter`
- **Parameter:** `category`
- **Method:** GET
### Payload Used
```
Gifts'||'1'=='1
```
(URL Encoded: `Gifts%27%7c%7c%271%27%3d%3d%271`)
### Retrieval Point
The HTTP response body increases significantly in size, displaying products that were previously hidden (unreleased).

---
## IMPACT
**Information Disclosure:** The attacker can bypass filters to view hidden or unreleased data. In other contexts, this same vulnerability could be used to bypass authentication (Login bypass) or extract sensitive fields using JavaScript inference.

---
## FIX / MITIGATION
1. **Sanitize Input:** Escape special characters (quotes, backslashes) before processing.
2. **Avoid JavaScript Queries:** Do not use `$where` or string-based JavaScript evaluation in MongoDB queries. Use native MongoDB operators (e.g., `find({ category: "Gifts" })`) which automatically treat input as data, not code.
3. **Type Checking:** Ensure the `category` parameter is strictly a string and does not contain illegal characters.
---
## KEY LEARNING
- **Syntax vs. Logic:** Unlike SQLi where you comment out the rest of the query (`--`), in NoSQL/JavaScript injection, you often just append a logical `OR` condition (`||`) to make the whole statement true.
- **The Null Byte Alternative:** Another valid solution for this lab is `Gifts'%00`. This tricks MongoDB into ignoring subsequent checks (like `&& this.released == 1`) by terminating the string early.

---
