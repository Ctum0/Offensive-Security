# Stored XSS into HTML Context (Nothing Encoded)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Stored XSS into HTML context with nothing encoded_
Vulnerability: _Stored Cross-Site Scripting (XSS)_

---
## DESCRIPTION
The application contains a blog with a comment section. User-submitted comments are saved to the backend database and subsequently displayed to any user who visits the blog post. The application fails to sanitize or encode the comment data before rendering it in the browser.

---
## ROOT CAUSE
**Lack of Output Encoding (Persistent):** The application treats the `comment` field as trusted text. When it retrieves the comment from the database and embeds it into the HTML page, it does not convert characters like `<` and `>` into HTML entities. This allows stored JavaScript to be executed by the browser of any visitor.

---
## ATTACK SCENARIO
1. **Injection:** The attacker navigates to a blog post and submits a comment containing the payload `<script>alert(1)</script>`.    
2. **Storage:** The server accepts the payload and saves it permanently in the comments database table.
3. **Execution:** A victim (or the attacker) views the blog post. The server fetches the comment from the database and serves it.
4. **Trigger:** The victim's browser parses the HTML, encounters the script tag, and executes the alert.

---
## PROOF OF CONCEPT
### Injection Point
- **Feature:** Blog Comments
- **Parameter:** `comment`
- **Context:** HTML Body (Stored)
### Payload Used
```html
<script>alert(1)</script>
```
### Request Flow
- **POST** to `/post/comment` with the payload.
- **GET** `/post?postId=x` to verify execution.

---
## IMPACT
**High/Critical:** Unlike Reflected XSS, this attack is persistent. It does not require the victim to click a specific link. Any user (including administrators) who simply views the page will be compromised, potentially leading to mass session hijacking or privilege escalation.

---
## FIX / MITIGATION
**Output Encoding:** Ensure that all user-supplied data retrieved from the database is strictly HTML-encoded before being rendered in the browser.

---
## KEY LEARNING
**Persistence Amplifies Risk.** Reflected XSS targets a specific user at a specific time (via a link). Stored XSS creates a "landmine" that stays on the server, attacking every visitor automatically. This is why testing inputs that save data (comments, bio fields, names) is critical.

---
