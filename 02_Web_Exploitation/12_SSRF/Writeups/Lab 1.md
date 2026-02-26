# Basic SSRF against the local server
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Basic SSRF against the local server_
Vulnerability: _Server-Side Request Forgery (SSRF)_

---
## DESCRIPTION
The application's stock check feature is vulnerable to Server-Side Request Forgery(SSRF). An attacker can manipulate the API endpoint to force the backend server to make unauthorized HTTP requests to internal infrastructure. This allows the attacker to bypass external access controls and interact with restricted administrative interface hosted on the local loopback address.

---
## ROOT CAUSE
The application implicitly trusts user-supplied input within the `stockApi` parameter. It fetches the requested URL without performing strict server-side validation or enforcing an allowlist. Consequently, the backend server executes requests to internal interfaces on behalf of the unauthenticated attacker.

---
## ATTACK SCENARIO
1. Intercepts the legitimate stock check HTTP POST request.
2. Modifies the `stockApi` parameter from its intended external URL to target the local loopback interface (`http://localhost/admin`).
3. Forwards the request and verifies unauthorized access to the administrative panel.
4. Identifies the specific administrative endpoint responsible for user deletion.
5. Executes a secondary SSRF payload targeting the deletion endpoint to permanently remove the victim user.

---
## PROOF OF CONCEPT
Target Endpoint: `POST /product/stock`
Exploit Payload(User Deletion):
```HTTP
stockApi=http://localhost/admin/delete?username=carlos
```

---
## IMPACT
This vulnerability results in critical privilege escalation and unauthorized data destruction. The attacker leverages the trusted backend server to bypass external perimeter security, enabling the execution of administrative functions such as arbitrary account deletion.

---
## FIX / MITIGATION
Implement strict server-side validation using an allowlist of permitted external domains for the stock check functionality. Block all requests targeting private IP address ranges, loopback interfaces (e.g., `127.0.0.1`, `localhost`), and internal routing hostnames.

---
## KEY LEARNING
Never implicitly trust user-supplied URLs; always validate and restrict backend HTTP requests to a strict, mathematically defined allowlist to prevent internal infrastructure compromise.

---
