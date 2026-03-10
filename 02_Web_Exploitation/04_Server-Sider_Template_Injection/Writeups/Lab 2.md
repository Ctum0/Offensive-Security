# Basic Server-Side Template Injection (Code Context)
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Basic Server-Side Template Injection (Code Context)_

---
## DESCRIPTION
The application contains a "Preferred Name" feature that allows users to customize their display name on blog posts. The application processes this input using a **Tornado (Python)** template engine. Due to unsafe implementation, the application evaluates user-supplied input as Python code within a template expression, rather than treating it as a static string.

---
## ROOT CAUSE
**Unsafe Template Evaluation (Code Context):** The developer likely placed user input directly inside a Python statement within the template (e.g., `{{ user.name }}`).
- **Vulnerability:** The engine allows the use of standard Python syntax (`{{ }}`) and does not sandbox the environment effectively.
- **Mechanism:** Attackers can break out of the intended string or variable context and execute arbitrary Python expressions.

---
## ATTACK SCENARIO
1. **Identification:** The attacker logs in and navigates to the "Preferred Name" update form.
2. **Detection:** The attacker submits `${{7*7}}` and observes a Python traceback error, identifying the engine as **Tornado**.
3. **Payload Construction:** Since the `import` statement is invalid inside a template expression, the attacker uses the built-in `__import__('os')` function to dynamically load the operating system module.
4. **Exploitation:** The attacker submits the payload `{{__import__('os').system('rm /home/carlos/morale.txt')}}`.
5. **Execution:** When the page renders, the Tornado engine evaluates the expression, executes the system command to delete the file, and renders the return code (`0`) on the page.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/my-account/change-blog-post-author-display`
- **Parameter:** `blog-post-author-display`
- **Method:** POST (Authenticated)
### Payload Used
```python
{{__import__('os').system('rm /home/carlos/morale.txt')}}
```
### Retrieval Point
The return code of the system command (`0` for success) is rendered in the HTTP response where the user's name would normally appear.

---
## IMPACT
**Critical (Remote Code Execution):** The vulnerability allows for full Remote Code Execution (RCE). An attacker can read, modify, or delete arbitrary files on the server (as demonstrated by deleting `morale.txt`) and potentially compromise the entire underlying infrastructure.

---
## FIX / MITIGATION
- **Input Validation:** Implement strict allowlisting for user input (e.g., alphanumeric characters only) before processing.
- **Context-Aware Output Encoding:** Ensure user input is treated strictly as data and never concatenated into template logic.
- **Sandboxing:** If dynamic templates are required, run the template engine in a restricted sandbox that disables access to dangerous built-ins like `__import__`, `os`, and `sys`.

---
## KEY LEARNING
- **Context is Key:** In "Code Context" injections, the input is often already inside a code block. The payload must be valid Python syntax that returns a string or value the template can render.
- **Bypassing Import Restrictions:** When standard `import` statements are blocked or syntactically invalid (as they are statements, not expressions), use `__import__('module')` to load libraries inline.

---
