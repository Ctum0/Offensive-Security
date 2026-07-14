# CSRF where token validation depends on request method
---
## TARGET
PortSwigger Web Security Academy  
Lab: _CSRF where token validation depends on request method_
Vulnerability: _Cross-Site Request Forgery (CSRF)_

---
## DESCRIPTION
This application's change email functionality is vulnerable to CSRF due to flawed token validation logic. While the system successfully enforces CSRF defenses on POST requests, it completely omits these checks for GET requests. An attacker exploits this by forcing an authenticated victim's browser to execute a state-changing GET request via a hidden HTML image tag.

---
## ROOT CAUSE
The backend server conditionally validates anti-CSRF tokens based on the HTTP request method. It strictly verifies tokens for POST requests but fails to enforce the same validation when the endpoint is accessed via a GET request.

---
## ATTACK SCENARIO
1. Identifies that the `/my-account/change-email` endpoint processes state-changing actions via GET requests.
2. Observes that the server drops the CSRF token validation requirement entirely when the GET method is used.
3. Crafts a malicious HTML payload utilizing a zero-pixel `<img>` tag, setting the `src` attribute to the vulnerable endpoint with the desired email parameter.
4. Hosts the payload on an attacker-controlled exploit server.
5. Delivers the exploit URL to the authenticated victim.
6. Executes the GET request silently when the victim's browser attempts to load the image source, forcibly updating the account email address.

---
## PROOF OF CONCEPT
**Target Endpoint:** `GET /my-account/change-email`
**Exploit Payload:** 
```HTML
<html>
<body>
  <h1>Hello World!</h1>
  <img src="https://0ac100a304cceb67802bad5100c7004e.web-security-academy.net/my-account/change-email?email=sithum@nn.co" width="0" height="0" border="0">
</body>
</html>
```

---
## IMPACT
This vulnerability enables full account takeover. By forcibly changing victim's registered email address without authorization, the attacker can execute a subsequent password reset to gain total control of the account.

---
## FIX / MITIGATION
Enforce CSRF token validation uniformly across all HTTP methods capable of executing state-changing actions. Furthermore, strictly adhere REST principles by configuring the application reject any state-changing actions submitted via GET requests.

---
## KEY LEARNING
Security controls must be uniformly enforced across all input vectors; relying on the HTTP request method to dictate validation requirements inherently creates bypass vulnerabilities.

---
