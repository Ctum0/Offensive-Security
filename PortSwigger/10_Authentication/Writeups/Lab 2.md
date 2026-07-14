# Broken brute-force protection, IP block
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Broken brute-force protection, IP block_
Vulnerability: _Authentication Vulnerability(Logic Flaw)_

---
## DESCRIPTION
The application implements an IP-based brute-force protection mechanism that is inherently flawed. While the system monitors consecutive failed login attempts originating from a single IP address, the block counter instantly resets upon any successful authentication from that same IP. An attacker can exploit this logic to circumvent the lockout mechanism and conduct an indefinite brute-force campaign against targeted accounts.

---
## ROOT CAUSE
The pivotal flaw resides in the authentication system's state tracking. The application fails to isolate failed login counters per targeted username. Because a successful authentication by an attacker-controlled account resets the global IP penalty counter, the system's brute-force protection suffers from a critical architectural oversight. 

---
## ATTACK SCENARIO
1. Initiates an authentication request against the target account ( `Carlos` ) using a candidate password from a wordlist (Counter = 1).
2. Initiates a second authentication request against the target account with the next candidate password (Counter = 2).
3. Authenticates successfully into an attacker-controlled account (`wiener` ) using known valid credentials, forcing the source IP's failure counter to reset (Counter = 0).
4. Iteratively repeats this cycle, systematically bypassing thr IP block until the target password is recovered.

---
## PROOF OF CONCEPT
**Execution Method:** Automated vi a python script or Burp Suite intruder utilizing a macro loop.
**Payload Sequence:** 
	Request 1: POST /login (username=carlos, password = [wordlist_item_1] )
	Request 2: POST /login (username=carlos, password = [wordlist_item_2])
	Request 3: POST /login (username=wiener, password=peter) -> Triggers Counter reset

---
## IMPACT
This deficiency facilitates unmitigated brute-force attacks. It directly enables systematic compromise of user accounts, leading to unauthorized access, data exposure, and potential privilege escalation.

---
## FIX / MITIGATION
Implement a multi layered brute-force defense mechanism. Isolate the failed login counter strictly per username, ensuring that a successful login to one account does not reset the failure counter for the IP address globally. Additionally, implement exponentially increasing time delays for failed login attempts.

---
## KEY LEARNING
Security controls must not rely on overly broad metrics (like IP alone) without considering account specific contexts; an IP block is useless if the attacker controls the reset mechanism. 

---
