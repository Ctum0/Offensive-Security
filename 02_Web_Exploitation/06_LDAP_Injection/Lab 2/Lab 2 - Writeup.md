# Lab 2: Blind LDAP Injection - Data Exfiltration
---
## TARGET
**Self-Hosted Lab** (Docker/Python/OpenLDAP) **Objective:** Exfiltrate the hidden `description` attribute from the `admin` user.

---
## DESCRIPTION
The application's security posture was improved by suppressing the display of LDAP attributes. Upon a successful query, the application only returns the string `STATUS: SUCCESS`. This requires the use of a Boolean-based inference attack to dump data one character at a time.

---
## INFRASTRUCTURE BUILD
**Vulnerable Code Snippet (`app.py`):** The search filter remains vulnerable to injection, but the retrieval logic is now "Blind."
```python
if conn.entries:
    status = "SUCCESS" # No data returned to the user
else:
    status = "FAILURE"
```
**Deployment:** The lab was redeployed with a modified Flask frontend while maintaining the same OpenLDAP backend containing the seeded description: `The supreme leader`.

---
## ROOT CAUSE
**Improper Input Sanitization (CWE-90):** The injection point in the `username` field allows an attacker to manipulate the query tree. Even without direct data output, the **conditional response** (SUCCESS vs FAILURE) creates a side-channel for data leakage.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker confirms that `admin` is a valid user.
2. **Inference:** The attacker tests `admin)(description=A*` and receives `FAILURE`.
3. **Validation:** The attacker tests `admin)(description=T*` and receives `SUCCESS`.
4. **Automation:** A Python script is developed to iterate through a character set, appending each successful character to the known prefix until the full string is recovered.
---
## PROOF OF CONCEPT
### Injection Point
- **Field:** `username`
- **Logic:** `admin)(description=[GUESS]*`
### Payload Used
- **Username:** `admin)(description=The s*`
- **Password:** `*`
### Retrieval Point
The `<h2>` tag containing the status message (`SUCCESS` or `FAILURE`).

---
## IMPACT
**High:** Sensitive organizational information stored within the directory (emails, phone numbers, notes) can be systematically dumped by an unauthorized user.

---
## FIX / MITIGATION
1. **Parameterized Queries:** Use built-in library functions to handle search filters safely.
2. **Input Filtering:** Strictly allow only alphanumeric characters in the username field.
3. **Generic Errors:** Ensure that error messages and response times are consistent to prevent both boolean and timing-based inference.

---