# User ID controlled by request parameter with data leakage in redirect
---
## TARGET
PortSwigger Web Security Academy  
Lab: _User ID controlled by request parameter with data leakage in redirect_
Vulnerability: _Broken Access Control (Information Disclosure via Redirect)_

---
## DESCRIPTION
The application is vulnerable to sensitive data leakage within the HTTP response body of a redirect. When a user attempts to access another user's account page (e.g., `/my-account?id=carlos`), the application correctly identifies the access violation and redirects the user to the login page. However, it fails to terminate the script execution before writing the sensitive account details (including the API key) into the response body.

---
## ROOT CAUSE
**Improper Error Handling & Execution Flow:** The server-side code retrieves the sensitive data and populates the response buffer _before_ finalizing the access control check. When the check fails, the server sends a `302 Found` header to redirect the user but sends the populated buffer (containing the victim's data) along with it.

---
## ATTACK SCENARIO
1. **Authentication:** The attacker logs in with valid credentials (`wiener:peter`).
2. **Interception:** The attacker captures the request to their "My Account" page using a proxy (Burp Suite).
3. **Tampering:** The attacker modifies the `id` parameter from `wiener` to `carlos`.
4. **Capture:** The attacker sends the request to the Repeater tool to inspect the raw response.
5. **Extraction:** The server returns a `302 Redirect` status. The attacker inspects the response body (which a browser would normally ignore) and finds Carlos's API key leaked in the HTML.

---
## PROOF OF CONCEPT
**Request:**
```HTTP
GET /my-account?id=carlos HTTP/1.1
Host: <LAB-ID>.web-security-academy.net
Cookie: session=WIENER_SESSION_TOKEN
```

**Response (Leaked Data):**
```HTTP
HTTP/1.1 302 Found
Location: /login
Content-Length: 3421

...
<div id="account-content">
    Your API Key is: v8x9... (Carlos's Key)
</div>
...
```

---
## IMPACT
**High:** Information Disclosure. An unauthorized attacker can retrieve sensitive account information (PII, API Keys) of any user despite the application attempting to block access.

---
## FIX / MITIGATION
1. **Early Exit:** Ensure the application calls `exit()`, `die()`, or `return` immediately after setting a redirect header to prevent further code execution.
2. **Order of Operations:** Perform all access control checks _before_ retrieving any sensitive data from the database.

---
## KEY LEARNING
**Browsers Hide Redirect Bodies.** A standard browser automatically follows `302` redirects, discarding the response body. To find this vulnerability, you must use a proxy tool (like Burp Suite) or a script that disables auto-redirects (`allow_redirects=False`) to see what the server is actually sending.

---
