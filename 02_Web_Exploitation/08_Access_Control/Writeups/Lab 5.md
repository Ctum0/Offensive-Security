# URL-based access control can be circumvented
---
## TARGET
PortSwigger Web Security Academy  
Lab: _URL-based access control can be circumvented_
Vulnerability: _Broken Access Control (Filter Bypass via `X-Original-URL`)_

---
## DESCRIPTION
The application infrastructure uses a front-end reverse proxy or WAF to restrict access to the `/admin` path. However, the back-end framework is configured to recognize the non-standard `X-Original-URL` header. This header allows a user to override the URL path in the eyes of the application logic while the front-end security filter only sees and validates the "innocent" root URL.

---
## ROOT CAUSE
**Inconsistent URL Parsing:** There is a discrepancy between how the front-end security filter and the back-end application framework interpret the request. The front-end blocks based on the request line URL, but the back-end gives precedence to the `X-Original-URL` header to determine which functionality to execute, effectively bypassing the security perimeter.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker attempts to access `/admin` and receives a "403 Forbidden" or "Access Denied" response from the front-end system.
2. **Discovery:** The attacker tests for framework-specific headers like `X-Original-URL` or `X-Rewrite-URL`.
3. **Bypass:** The attacker sends a request to the root directory (`/`)—which the front-end allows—but adds the header `X-Original-URL: /admin`.
4. **Verification:** The back-end processes the header and serves the admin panel through the root path.
5. **Exploitation:** The attacker uses the same header to reach the deletion endpoint: `X-Original-URL: /admin/delete?username=carlos`.

---
## PROOF OF CONCEPT
**Manual Exploit Steps:**
1. Access the lab home page.
2. Attempt to browse to `/admin`. Notice the "Access denied" message.
3. Intercept the request in Burp Suite.
4. Change the request line to `GET / HTTP/1.1`.
5. Add the header: `X-Original-URL: /admin`. Observe that the admin panel is now visible.
6. Send a new request to `GET /?username=carlos HTTP/1.1` with the header `X-Original-URL: /admin/delete`.
**Malicious Request:**
```HTTP
GET /?username=carlos HTTP/1.1
Host:0a0800e70492804b804b5d1b00f00051.web-security-academy.net
X-Original-URL: /admin/delete
```
---
## IMPACT
**Critical:** Complete bypass of front-end security controls. This allows unauthenticated attackers to reach sensitive administrative endpoints, leading to full system compromise or data deletion.

---
## FIX / MITIGATION
1. **Disable Override Headers:** Configure the back-end framework to ignore `X-Original-URL`, `X-Rewrite-URL`, and similar headers if they are not required.
2. **Unified Access Control:** Implement security checks at the application level (back-end) rather than relying solely on front-end URL filtering.
3. **Header Sanitization:** Ensure the front-end proxy strips or overrides these headers before passing requests to the back-end.
---
## KEY LEARNING
**The Front-End is not the Source of Truth.** Never assume that a WAF or Reverse Proxy is the final word on security. Differences in how components in a tech stack parse headers or URLs create "blind spots" that attackers exploit to tunnel malicious requests into the back-end.

---
