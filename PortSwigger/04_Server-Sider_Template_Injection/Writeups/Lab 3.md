# Server-Side Template Injection using Documentation
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Server-Side Template Injection using Documentation_

---
## DESCRIPTION
The lab functionality allows privileged users (`content-manager`) to edit the HTML template used for product pages. The application uses the **FreeMarker** (Java) template engine to render these pages. Due to the lack of a secure sandbox or input sanitization, the application allows the instantiation of arbitrary Java classes via the template's built-in `?new()` function.

---
## ROOT CAUSE
**Insecure Template Configuration (FreeMarker):** The FreeMarker engine is configured to allow the `?new()` built-in function, which can instantiate utility classes implemented in the `freemarker.template.utility` package. Specifically, the `Execute` class is exposed, which provides a direct interface to the underlying OS shell.

---
## ATTACK SCENARIO
1. **Access:** The attacker logs in with `content-manager` credentials and navigates to the template editor (`/product/template`).
2. **Identification:** The attacker injects `${7*7}`. The preview renders `49`, confirming a template engine that uses `${}` syntax (likely FreeMarker or similar).
3. **Research:** Consulting FreeMarker documentation reveals that the `freemarker.template.utility.Execute` class exists to run system commands.
4. **Exploitation:** The attacker constructs a payload to instantiate this class and execute `rm /home/carlos/morale.txt`.
5. **Execution:** Clicking "Preview" forces the server to parse the template, instantiate the object, and execute the shell command.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/product/template?productId=1`
- **Parameter:** `template`
- **Method:** POST (Action: Preview)
### Payload Used
```Java
${"freemarker.template.utility.Execute"?new()("rm /home/carlos/morale.txt")}
```
### Retrieval Point
The output of the command (if any) is rendered in the "Preview" section of the HTML response. For `rm`, the output is empty, but the success is confirmed by the lab solved banner.

---
## IMPACT
**Critical (Remote Code Execution):** The attacker has achieved arbitrary code execution on the server. This allows for total system compromise, including data exfiltration, modification of application logic, and access to internal network resources.

---
## FIX / MITIGATION
1. **Disable Dangerous Built-ins:** Configure FreeMarker to disable the `?new()` built-in entirely using `setNewBuiltinClassResolver(TemplateClassResolver.ALLOW_NOTHING)`.
2. **Sandboxing:** Use a `ClassResolver` to strictly allowlist only safe classes that can be instantiated.
3. **Principle of Least Privilege:** Ensure the web application user runs with minimal OS permissions, preventing the modification of sensitive files like `morale.txt`.

---
## KEY LEARNING
- **RTFM (Read The Manual):** Template engines often have "Utility" classes designed for developers (like `Execute` or `ObjectConstructor`) that become security flaws when exposed to users. Reading the official documentation for "deprecated" or "utility" classes is a primary recon step in SSTI.
- **Java SSTI:** Unlike Python/Ruby, Java SSTI often requires instantiating a specific class (`?new()`) rather than just importing a module.

---
