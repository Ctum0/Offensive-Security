# Unprotected admin functionality with unpredictable URL
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Unprotected admin functionality with unpredictable URL_
Vulnerability: _Broken Access Control (Information Disclosure via Client-Side Code)_

---
## DESCRIPTION
The application hosts an administrative panel at an unpredictable URL (e.g., `/admin-x9d...`) to prevent access by unauthorized users. However, this sensitive URL is dynamically generated and disclosed within the client-side JavaScript code. The application fails to enforce server-side access controls, allowing any user who discovers the URL to access administrative functions.

---
## ROOT CAUSE
**Information Disclosure & Security by Obscurity:** The application relies on the secrecy of the URL path for security. The path is leaked via a JavaScript `setAttribute` call in the HTML source, allowing attackers to extract it manually and bypass the intended restriction.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker inspects the page source code (Ctrl+U) or uses Browser Developer Tools (F12).
2. **Discovery:** The attacker searches for keywords like `admin`, `panel`, or `setAttribute`.
3. **Extraction:** The attacker locates the JavaScript line `adminPanelTag.setAttribute('href', '/admin-xxxxx')` and copies the path.
4. **Exploitation:** The attacker manually appends this path to the base URL in the browser address bar to access the panel.
5. **Action:** The attacker locates the "Delete" button for user `carlos` and clicks it to execute the deletion.
---
## PROOF OF CONCEPT
**Manual Extraction:**
1. Open the lab in a browser.
2. Right-click -> **View Page Source** .
3. Search (Ctrl+F) for `adminPanelTag`.
4. Observe the code:
```JavaScript
var adminPanelTag = document.createElement('a');
adminPanelTag.setAttribute('href', '/admin-2g9s8z'); // Example path
```
**Manual Exploit:**
1. Copy the path `/admin-2g9s8z`.
2. Paste it into the browser URL bar: `https://<LAB-ID>.web-security-academy.net/admin-2g9s8z`.
3. Click "Delete" next to user `carlos`.

---
## IMPACT
**Critical:** Complete compromise of administrative functionality, allowing for unauthorized user deletion and potential system takeover.

---
## FIX / MITIGATION
1. **Server-Side Authorization:** Implement proper access control checks (Authorization) on the server side for all administrative endpoints.
2. **Remove Secrets from Client Code:** Do not expose sensitive paths or logic in client-side JavaScript.

---
## KEY LEARNING
**Obscurity is not Security.** Hiding a link in JavaScript or using a random URL does not secure an endpoint. If the client (browser) needs to know the URL, the attacker can find it. Always verify user privileges on the server.

---
