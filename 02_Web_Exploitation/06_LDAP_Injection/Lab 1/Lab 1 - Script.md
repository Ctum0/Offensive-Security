# Lab 1: LDAP Authentication Bypass via Wildcard Injection

---
## TARGET
**Self-Hosted Lab** (Docker/Python/OpenLDAP) **Objective:** Log in as the `admin` user without knowing the password.

---
## DESCRIPTION
A custom-built Python Flask application connects to an OpenLDAP backend to authenticate users. The application accepts a username and password, then constructs an LDAP search filter to verify credentials. The goal is to manipulate the filter logic to bypass the password check.

---
## INFRASTRUCTURE BUILD

**Vulnerable Code Snippet (`app.py`):** The application uses Python f-strings to construct the query, which is vulnerable to injection.
```python
# The critical flaw: Direct string concatenation of user input
search_filter = f"(&(cn={user})(userPassword={pw}))"
```

**Deployment:** The environment runs on a private Docker network (`ldap-net`). It consists of:
1. **Backend:** `osixia/openldap` container pre-seeded with admin credentials.
2. **Frontend:** A Flask web app exposing port 5000.
---
## ROOT CAUSE
**Improper Input Sanitization (CWE-90):** The application fails to sanitize special LDAP characters (specifically `*`, `(`, `)`). The LDAP protocol treats `*` as a wildcard. When injected into an attribute filter, it changes the logic from "Exact Match" to "Presence Check" (i.e., does this attribute exist?).

---
## ATTACK SCENARIO
1. **Analysis:** The attacker identifies the login form creates a standard AND filter: `(&(cn=user)(userPassword=pass))`.
2. **Hypothesis:** If the password field is replaced with a wildcard `*`, the database will check if the user _has_ a password, rather than _what_ the password is.
3. **Execution:** The attacker submits `admin` as the user and `*` as the password.
4. **Result:** The query becomes `(&(cn=admin)(userPassword=*))`. Since the admin account has a password attribute, this evaluates to TRUE.
---
## PROOF OF CONCEPT
### Injection Point
- **URL:** `http://localhost:5000/`
- **Parameter:** `password` (POST Body)
### Payload Used
- **Username:** `admin`
- **Password:** `*`
### Retrieval Point
The application returns a "LOGIN SUCCESS" message and displays the user's details (Common Name, Phone, Description), confirming full administrative access.

---
## IMPACT
**Critical:** Complete authentication bypass allowing unauthorized access to the administrative account.

---
## FIX / MITIGATION
1. **Escaping:** Use `ldap3.utils.conv.escape_filter_chars` to sanitize all user input before insertion.
2. **Library Features:** Use the LDAP library's abstraction layers rather than raw string construction for filters.
---