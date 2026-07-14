# Exploiting XXE to perform SSRF attacks
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Exploiting XXE to perform SSRF attacks_
Vulnerability: _XML External Entity (XXE) Injection / Server-Side Request Forgery (SSRF)_

---
## DESCRIPTION
The application's XML parsing functionality is vulnerable to XML External Entity (XXE) injection. An attacker exploits this flaw to execute a Server-Side Request Forgery (SSRF) attack against the internal AWS EC2 metadata endpoint. By iteratively enumerating the metadata directories, the attacker extracts highly sensitive cloud infrastructure credentials.

---
## ROOT CAUSE
The backend XML parser is misconfigured to resolve external entities and implicitly trusts user-supplied Document Type Definitions (DTDs). Consequently, the application allows an attacker to weaponize the parser, forcing the server to execute unintended outbound HTTP requests to the internal, non-routable IP address (`169.254.169.254`).

---
## ATTACK SCENARIO
1. Intercepts the stock check HTTP POST request containing the XML payload.
2. Injects a malicious DTD defining an external entity (`xxe`) that targets the simulated EC2 metadata endpoint (`http://169.254.169.254/`).
3. References the external entity within the `<productId>` node (`&xxe;`).
4. Forwards the request and analyzes the reflected response to identify available directory paths (e.g., `/latest`).
5. Iteratively appends the discovered paths to the entity URL to traverse the directory structure (`/latest/meta-data/iam/security-credentials/admin`).
6. Extracts the AWS IAM secret access key reflected in the final server response.

---
## PROOF OF CONCEPT
**Target Endpoint:** `POST /product/stock`
**Exploit Payload (Final Iteration):**
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

---
## IMPACT
This vulnerability results in the complete compromise of the underlying cloud infrastructure. By obtaining valid IAM secret access keys, an unauthenticated attacker gains unauthorized access to the AWS environment, enabling data exfiltration, resource manipulation, and lateral movement.

---
## FIX / MITIGATION
Manually disable the processing of Document Type Definitions (DTDs) and completely restrict the resolution of external entities within the XML parser. Furthermore, implement network-layer security controls (such as `iptables` or AWS Security Groups) to block the application server from querying the `169.254.169.254` metadata IP address unless explicitly required.

---
## KEY LEARNING
XXE vulnerabilities serve as a direct vector for SSRF; internal cloud metadata endpoints are critical targets and must be mathematically isolated from application-layer requests.

---
