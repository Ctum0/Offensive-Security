# Blind OS command injection with time delays
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Blind OS command injection with time delays_

---
## DESCRIPTION
The application's feedback function allows users to submit messages. The backend executes a shell command using the user-supplied details (likely to send an email). The vulnerability is **Blind**: the application does not return the command's output in the HTTP response. The goal is to prove execution by causing a 10-second time delay.

---
## ROOT CAUSE
The application concatenates user input (specifically the email field) into a system shell command without sanitization. Because the output is discarded or not displayed, standard "echo" payloads do not work visually.

---
## ATTACK SCENARIO
- **Probe:** The attacker submits standard feedback.
- **Injection:** The attacker attempts to inject time-based commands into the `email` field.
    - Payload logic: `email_address || ping -c 10 127.0.0.1 ||`
- **Execution:**
    - The server executes the first part (email command).
    - The `||` (OR) or `;` (Separator) allows the second command (`ping`) to run.
    - `ping -c 10` forces the server to wait for 10 pings (~10 seconds) before finishing the script.
- **Confirmation:** The attacker observes that the HTTP response takes >10 seconds to arrive, confirming the injection.

---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `/feedback/submit`
- **Parameter:** `email`
- **Method:** POST
### Payload Used
```
||ping -c 10 127.0.0.1||
```
(Note: `ping -c 10` sends 10 packets, taking roughly 10 seconds on Linux).
### Result
**Response Time:** > 10,000ms (10 seconds).

---
## IMPACT
High. Although blind, this confirms Remote Code Execution (RCE). An attacker could trigger reverse shells or exfiltrate data via DNS (Out-of-Band) to fully compromise the server.

---
## FIX / MITIGATION
- **Use APIs:** Use language-specific libraries (e.g., Python's `smtplib`, JavaMail) instead of calling OS commands like `mail` or `sendmail`.
- **Input Validation:** Strictly validate email formats using Regex.
- **Least Privilege:** Ensure the web user cannot execute commands like `ping`, `wget`, or `curl`.

---
## KEY LEARNING
- **Blind does not mean Safe:** Just because you don't see the output doesn't mean the command failed.
- **Time as an Oracle:** Time delays (`ping`, `sleep`) are the most reliable way to verify Blind RCE when Out-of-Band (DNS) interaction isn't available.

---
