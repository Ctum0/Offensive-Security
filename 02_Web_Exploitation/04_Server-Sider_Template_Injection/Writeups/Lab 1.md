# Basic server-side template injection
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Basic server-side template injection_

---
## DESCRIPTION
The application allows users to view a "message" via a URL parameter. This message is processed by an ERB (Embedded Ruby) template engine. The application vulnerably concatenates the user input directly into the template string rather than passing it as a data object. The goal is to execute arbitrary code to delete the file `/home/carlos/morale.txt`.

---
## ROOT CAUSE
**Unsafe Template Construction (Concatenation):** The developer likely wrote code similar to: `template = "The message is: " + params['message']` `render(template)`
Instead of the secure method: `render("The message is: <%= message %>", {message: params['message']})`
This allows an attacker to close the intended string or inject new ERB tags (`<%= ... %>`) that the engine executes as Ruby code.

---
## ATTACK SCENARIO
- **Identification:** The attacker notices the `message` parameter is reflected on the page.
- **Fuzzing:** The attacker tests for template injection using ERB syntax: `<%= 7*7 %>`.
- **Confirmation:** The server renders `49`, confirming that Ruby code is being executed.
- **Exploitation:** The attacker uses the Ruby `system()` function to execute a shell command.
    - Payload: `<%= system("rm /home/carlos/morale.txt") %>`
- **Result:** The server executes the `rm` command, deleting the file.
---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/`
- **Parameter:** `message`
- **Method:** GET
### Payload Used
```Ruby
<%= system("rm /home/carlos/morale.txt") %>
```
### Response Snippet
The function `system()` usually returns `true` if the command succeeds.
```
...
true
...
```

---
## IMPACT
**Critical.** Full Remote Code Execution (RCE). The attacker can read/write files, install malware, or pivot to the internal network.

---
## FIX / MITIGATION
- **Avoid Concatenation:** Never concatenate user input directly into a template string.
- **Pass Data Properly:** Use the template engine's built-in mechanism to pass variables (e.g., passing a context dictionary or array).
- **Sandboxing:** If user templates are required, run them in a restricted environment (though this is hard to do securely in Ruby).

---
## KEY LEARNING
- **Engine Fingerprinting:** The syntax `<%= ... %>` is highly specific to Ruby (ERB) and NodeJS (EJS). If `<%= 7*7 %>` returns `49`, it is almost certainly one of those two.
- **Ruby RCE:** In Ruby templates, the `system("command")` function is the quickest path to Remote Code Execution. It executes the shell command and returns `true` (if successful) or `false`.
- **Text vs. Code:** The difference between `<%= %>` (Output result) and `<% %>` (Execute silently) is crucial. Use the former for testing (to see the `49`) and the latter for stealthy attacks.

---
