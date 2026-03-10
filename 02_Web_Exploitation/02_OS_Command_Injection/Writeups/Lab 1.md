# OS command injection, simple case
---
## TARGET
PortSwigger Web Security Academy  
Lab: _OS command injection, simple case_

---
## DESCRIPTION
The application's "Check Stock" feature passes user input (Store ID) directly to a shell command without sanitization. The application returns the raw output of the command in the HTTP response. The goal is to inject the `whoami` command to reveal the current user.

---
## ROOT CAUSE
**Unsanitized Input in Shell Execution:** The application likely uses a function like `exec()` or `system()` (e.g., `stock_check.sh <product_id> <store_id>`) and fails to validate or escape the parameters. This allows an attacker to inject shell metacharacters (like `|`, `;`, `&`) to chain commands.

---
## ATTACK SCENARIO
1. **Identification:** The attacker identifies the `storeId` parameter in the stock check POST request as a potential injection point.
2. **Injection:** The attacker appends a pipe (`|`) and the command `whoami` to the store ID.
    - **Logic:** The shell sees `stock_check 1 1 | whoami`. It runs the stock check, then pipes the output (or simply runs next) to `whoami`.
3. **Execution:** The server executes `whoami` and returns the username (e.g., `peter-hO2bYB`) in the response body.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/product/stock`
- **Parameter:** `storeId`
- **Method:** POST
### Payload Used
```
1|whoami
```
### Result
```
peter-hO2bYB
```

---
## IMPACT
**Critical.** An attacker can execute arbitrary system commands with the privileges of the web server user. This can lead to full server compromise, data exfiltration, or installation of backdoors.

---
## FIX / MITIGATION
- **Avoid Shell Calls:** Use built-in API calls instead of shelling out to the OS (e.g., use a Python library instead of `os.system`).
- **Input Validation:** Whitelist allowed characters (e.g., integers only).
- **Parameterized Execution:** If shell execution is unavoidable, use functions that separate the command from the arguments (like Python's `subprocess.run(["cmd", "arg"])`) rather than string concatenation.

---
## KEY LEARNING
- **Command Separators:** The pipe `|` is a classic separator, but others exist (`&`, `;`, `\n`). If one is blocked, try others.
- **Context Matters:** Unlike SQL injection (where we talk to a database), here we are talking to the Linux/Windows shell. The payloads must follow shell syntax (bash/cmd.exe).
- **Raw Output:** In "Simple Case" scenarios, the application is helpful enough to print the `stdout` (standard output) of our injected command. This makes exploitation trivial compared to "Blind" scenarios.

---
