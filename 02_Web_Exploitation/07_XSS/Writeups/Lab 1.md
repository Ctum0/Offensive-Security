# Reflected XSS into HTML Context (Nothing Encoded)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Reflected XSS into HTML Context (Nothing Encoded)_
Vulnerability: _Reflected Cross-Site Scripting (XSS)_

---
## DESCRIPTION
The application contains a search function that receives user input via a URL parameter. This input is echoed back to the user within the HTML response body without any form of sanitization or output encoding. This allows an attacker to inject standard HTML tags, including JavaScript triggers.

---
## ROOT CAUSE
**Lack of Output Encoding:** The application takes the value of the `search` parameter and directly concatenates it into the HTML document structure. It fails to convert special characters (like `<` and `>`) into their HTML entity equivalents (`&lt;`, `&gt;`).

---
## ATTACK SCENARIO
1. **Discovery:** The attacker inputs a unique alphanumeric string (e.g., `test1234`) into the search bar to locate where the input is reflected in the source code.
2. **Analysis:** The source shows `<h1>0 search results for 'test1234'</h1>`. The input is inside a generic Header tag, not inside a JavaScript block or attribute.
3. **Exploitation:** The attacker injects a standard Cross-Site Scripting payload: `<script>alert(1)</script>`.
4. **Execution:** The browser parses the opening `<script>` tag and executes the JavaScript contained within it.

---
## PROOF OF CONCEPT
### Injection Point
- **URL Parameter:** `search`
- **Context:** HTML Body
### Payload Used
```html
<script>alert(1)</script>
```
### Retrieval Point (HTTP Request)
GET /?search=<script>alert(1)</script> HTTP/1.1

---
## IMPACT
**Medium/High:** Allows the execution of arbitrary JavaScript in the victim's browser. This can lead to session hijacking (stealing cookies), redirection to malicious sites, or unauthorized actions performed on behalf of the user.

---
## FIX / MITIGATION
**Output Encoding:** Implement context-aware output encoding. Since the data is being placed into the HTML body, convert all special characters to HTML entities before rendering.
- `<` becomes `&lt;`
- `>` becomes `&gt;`

---
## KEY LEARNING
**Context is King.** The payload `<script>alert(1)</script>` only worked because the input was reflected directly into the **HTML Body**.
- If the input had landed inside an attribute (e.g., `<input value="HERE">`), this payload would have failed (it would need to break out of the quote first).
- **Takeaway:** Always inspect the raw HTML source to verify **where** your input lands before crafting the payload.

---
