# Server-Side Template Injection with Information Disclosure (Django)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Server-side template injection with information disclosure via user-supplied objects_

---
## DESCRIPTION
The lab uses the **Django** framework (Python) to render product descriptions. The application inadvertently exposes sensitive objects to the template context. Specifically, the `settings` object is accessible, allowing attackers to read internal configuration variables, including the cryptographic `SECRET_KEY`.

---
## ROOT CAUSE
**Unsafe Context Exposure:** The developer likely passed the entire request context or a global configuration object into the template rendering engine (e.g., `render(request, 'template.html', locals())`). This violates the Principle of Least Privilege by exposing the sensitive `settings` object to the template environment.

---
## ATTACK SCENARIO
1. **Fingerprinting:** The attacker injects fuzz strings like `${{<%` into the template editor. The resulting error message explicitly mentions "Django", identifying the framework.
2. **Debug Analysis:** The attacker uses the Django built-in tag `{% debug %}` to list all available variables in the current context.
3. **Discovery:** The debug output reveals the presence of the `settings` object.
4. **Exploitation:** The attacker crafts a payload `{{ settings.SECRET_KEY }}` to render the value of the application's private key.
5. **Exfiltration:** The key is displayed in the preview window, harvested, and submitted to solve the lab.
---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/product/template?productId=1`
- **Parameter:** `template`
- **Method:** POST
### Payload Used
```Django
{{ settings.SECRET_KEY }}
```
### Retrieval Point
The `SECRET_KEY` is rendered as plaintext within the "Preview" section of the HTML response (`<div id="preview-result">`).

---
## IMPACT
**High (Information Disclosure / System Compromise):** The `SECRET_KEY` is the root of trust in Django applications. With this key, an attacker can:
- Forge valid session cookies (Account Takeover).
- Bypass CSRF protection.
- Generate valid password reset tokens.
- Sign arbitrary data trusted by the application.
---
## FIX / MITIGATION
- **Explicit Context Passing:** Only pass the specific variables required by the template (e.g., `{'product_name': product.name}`). Never pass `locals()` or the full `settings` object.
- **Audit Template Tags:** Ensure that debug mode is disabled in production (`DEBUG = False`), which prevents the `{% debug %}` tag from functioning or leaking stack traces.

---
## KEY LEARNING
- **The `{% debug %}` Tag:** In Django SSTI, always try `{% debug %}` first. It is the equivalent of `print(env)` and lists every object you can exploit.
- **Framework-Specific Gadgets:** Accessing configuration objects (like `settings` in Django, `config` in Flask/Jinja2, or `self` in Ruby) is a primary method for escalating from simple SSTI to Information Disclosure or RCE.

---
