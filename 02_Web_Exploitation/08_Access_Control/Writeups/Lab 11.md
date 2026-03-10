# Insecure Direct Object References
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Insecure Direct Object References_
Vulnerability: _Broken Access Control (Insecure Direct Object Reference - IDOR)_

---
## DESCRIPTION
The application allows users to download chat transcripts via a static URL pattern (e.g., `/download-transcript/2.txt`). The filenames are sequential integers. The application fails to verify if the requesting user is the owner of the file, allowing an attacker to access other users' chat logs by simply modifying the filename in the URL.

---
## ROOT CAUSE
**Insecure Direct Object Reference (IDOR):** The server exposes a direct reference to an internal implementation object (the file index `1.txt`) and fails to enforce authorization checks when that object is requested. It assumes that knowing the URL is equivalent to having permission to access it.

---
## ATTACK SCENARIO
1. **Reconnaissance:** The attacker engages the "Live Chat" feature and clicks "View Transcript".
2. **Analysis:** The attacker observes the download URL: `/download-transcript/2.txt`.
3. **Enumeration:** The attacker modifies the URL to `/download-transcript/1.txt` (decrementing the ID).
4. **Data Extraction:** The server returns the chat log for user `carlos`, which contains his password in plain text.
5. **Account Takeover:** The attacker uses the extracted password to log in to Carlos's account.

---
## PROOF OF CONCEPT
**Vulnerable Endpoint:**
```HTTP
GET /download-transcript/1.txt HTTP/1.1
```
**Extracted Data (Regex):** `password is (\w+)` -> Matches the password in the chat log.
**Manual Steps:**
1. Access `/download-transcript/1.txt`.
2. Copy the password found in the text.
3. Log in as `carlos`.

---
## IMPACT
**Critical:** Information Disclosure leading to Account Takeover. The leakage of credentials allows full compromise of victim accounts.

---
## FIX / MITIGATION
1. **Indirect References:** Use cryptographically secure random tokens (UUIDs) instead of sequential integers for filenames.
2. **Access Control:** Implement strict server-side checks to ensure the user requesting the file is the owner of the chat session.

---
## KEY LEARNING
**Static IDs are a Liability.** Sequential IDs (1, 2, 3...) used in direct file access are trivial to enumerate. Always validate ownership before serving static content, or serve content through a controller that handles authorization.

---
