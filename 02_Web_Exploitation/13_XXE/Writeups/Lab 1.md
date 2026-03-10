# Exploiting XXE using external entities to retrieve files
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Exploiting XXE using external entities to retrieve files_
Vulnerability: _XML External Entity (XXE) Injection_

---
## DESCRIPTION
The application's "Check stock" feature is vulnerable to XML External Entity (XXE) injection. The backend XML parser processes user-supplied Document Type Definitions (DTDs) without restrictions and reflects the parsed values in the HTTP response. An attacker can exploit this oversight to read sensitive local files directly from the server's filesystem.

---
## ROOT CAUSE
The backend XML parsing library is inherently misconfigured to support and resolve external entities. The application fails to sanitize user-supplied XML input, resulting in the implicit trust and execution of malicious DTDs during the parsing phase.

---
## ATTACK SCENARIO
1. Intercepts the legitimate stock check HTTP POST request containing the XML payload.
2. Injects a malicious Document Type Definition (DTD) that defines an external entity (`xxe`) pointing to the local system file `file:///etc/passwd`.
3. Modifies the `productId` XML node to reference the injected external entity (`&xxe;`).
4. Forwards the manipulated XML request to the backend server.
5. Extracts the contents of the `/etc/passwd` file, which the server reflects within the "Invalid product ID" error response.

---
## PROOF OF CONCEPT
**Target Endpoint:** `POST /product/stock`
**Exploit Payload:**
```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

---
## IMPACT
This vulnerability results in critical information disclosure via Local File Inclusion (LFI). An unauthenticated attacker can arbitrarily read sensitive configuration files, source code, and system data, facilitating deeper compromise of the underlying server infrastructure.

---
## FIX / MITIGATION
Manually disable the processing of Document Type Definitions (DTDs) and completely restrict the resolution of external entities within the XML parser's configuration. Alternatively, migrate data serialization formats from XML to safer alternatives, such as JSON, whenever mathematically possible.

---
## KEY LEARNING
XML parsers must never implicitly trust user-supplied DTDs; external entity resolution must be explicitly disabled to neutralize data exfiltration vectors.

---
