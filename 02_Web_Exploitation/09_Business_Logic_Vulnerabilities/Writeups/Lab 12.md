# Flawed enforcement of business rules
---
## TARGET
PortSwigger Web Security Academy  
Lab: _Flawed enforcement of business rules_
Vulnerability: _Business Logic Vulnerability (Flawed Purchasing Workflow)_

---
## DESCRIPTION
The application contains a critical business logic vulnerability within its purchasing workflow. Specifically, the system fails to validate the simultaneous application of multiple promotional codes. An attacker can exploit this flaw to circumvent the intended checkout workflow by alternately applying a new-user discount and a newsletter-signup discount. Because the application only verifies the most recently applied coupon against the current input, it permits an unlimited, altering sequence of coupon applications. 

---
## ROOT CAUSE
The primary deficiency lies in the applications validation logic. it fails to maintain proper state tracking of previously applied promotional codes during a single checkout session, allowing an attacker to repeatedly apply the same discounts without restriction.

---
## ATTACK SCENARIO
1. Extracts the initial discount code from the homepage and the secondary discount code from the newsletter signup alert.
2. Proceeds to the checkout interace.
3. Iteratively applied the first and second coupon codes in an alternating sequence(e.g., Code A , Code B, Code A).
4. Executes the final checkout process once the cart total reaches an arbitrary value of zero

---
## PROOF OF CONCEPT
**Injection Point:** Promotional code input field within the checkout window.
**Payload:** Alternating sequence of valid promotional codes(Code A, Code B).
**Retrieval Point:** The cart total successfully reduces to $0.00.

---
## IMPACT
This vulnerability is critical because it allows malicious actors to acquire merchandise at no cost resulting in direct and unmitigated financial loss to the organization.

---
## FIX / MITIGATION
Implement robust server-side validation to enforce a strict limit on the number of promotional codes applied per transaction. Additionally, introduce state-tracking for the user's cart session to ensure a specific discount code can only be validated and applied once per order.

---
## KEY LEARNING
Never assume users will adhere to the intended application workflow; always enforce strict server side state tracking and business logic validation.

---
